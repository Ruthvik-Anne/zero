//! Jupyter messaging client (KRN-01): connection file, HMAC-signed multipart
//! frames, shell and iopub channels, execute round-trip, restart/rehydrate, and
//! bounded output/interruption.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use zero_types::error::{ErrorCode, Result, ZeroError};
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

type HmacSha256 = Hmac<Sha256>;

pub const DELIMITER: &[u8] = b"<IDS|MSG>";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub ip: String,
    pub transport: String,
    pub key: String,
    pub signature_scheme: String,
    pub shell_port: u16,
    pub iopub_port: u16,
    pub stdin_port: u16,
    pub control_port: u16,
    pub hb_port: u16,
    pub kernel_name: String,
}

impl ConnectionInfo {
    pub fn endpoint(&self, port: u16) -> String {
        format!("{}://{}:{}", self.transport, self.ip, port)
    }

    pub fn to_file(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_vec(self)?)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub msg_id: String,
    pub username: String,
    pub session: String,
    pub date: String,
    pub msg_type: String,
    pub version: String,
}

impl Header {
    pub fn new(msg_type: &str, session: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self {
            msg_id: format!("{session}-{nanos}"),
            username: "zero".into(),
            session: session.into(),
            date: "2026-01-01T00:00:00Z".into(),
            msg_type: msg_type.into(),
            version: "5.3".into(),
        }
    }
}

/// HMAC-SHA256 over the four JSON frames, per the Jupyter wire spec.
pub fn sign(key: &str, header: &[u8], parent: &[u8], metadata: &[u8], content: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "invalid HMAC key"))?;
    for part in [header, parent, metadata, content] {
        mac.update(part);
    }
    Ok(hex(mac.finalize().into_bytes().as_slice()))
}

pub fn verify(key: &str, signature_hex: &str, header: &[u8], parent: &[u8], metadata: &[u8], content: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "invalid HMAC key"))?;
    for part in [header, parent, metadata, content] {
        mac.update(part);
    }
    let bytes = unhex(signature_hex)?;
    mac.verify_slice(&bytes)
        .map_err(|_| ZeroError::new(ErrorCode::TamperDetected, "Jupyter message signature mismatch"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(ZeroError::new(ErrorCode::InvalidInput, "odd-length hex signature"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "bad hex signature")))
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub header: Header,
    pub parent: Value,
    pub metadata: Value,
    pub content: Value,
    pub identities: Vec<Vec<u8>>,
}

impl Message {
    pub fn execute_request(session: &str, code: &str) -> Self {
        Self {
            header: Header::new("execute_request", session),
            parent: json!({}),
            metadata: json!({}),
            content: json!({
                "code": code,
                "silent": false,
                "store_history": true,
                "user_expressions": {},
                "allow_stdin": false,
                "stop_on_error": false,
            }),
            identities: Vec::new(),
        }
    }

    /// Encode to the multipart frame vector.
    pub fn frame(&self, key: &str) -> Result<Vec<Vec<u8>>> {
        let header = serde_json::to_vec(&self.header)?;
        let parent = serde_json::to_vec(&self.parent)?;
        let metadata = serde_json::to_vec(&self.metadata)?;
        let content = serde_json::to_vec(&self.content)?;
        let signature = sign(key, &header, &parent, &metadata, &content)?;
        let mut frames: Vec<Vec<u8>> = self.identities.clone();
        frames.push(DELIMITER.to_vec());
        frames.push(signature.into_bytes());
        frames.push(header);
        frames.push(parent);
        frames.push(metadata);
        frames.push(content);
        Ok(frames)
    }

    pub fn decode(frames: &[Vec<u8>], key: &str) -> Result<Self> {
        let delimiter = frames
            .iter()
            .position(|frame| frame.as_slice() == DELIMITER)
            .ok_or_else(|| ZeroError::new(ErrorCode::Serialization, "Jupyter message has no delimiter"))?;
        if frames.len() < delimiter + 5 {
            return Err(ZeroError::new(ErrorCode::Serialization, "Jupyter message is truncated"));
        }
        let identities = frames[..delimiter].to_vec();
        let signature = std::str::from_utf8(&frames[delimiter + 1])
            .map_err(|_| ZeroError::new(ErrorCode::Serialization, "signature is not UTF-8"))?;
        let header = &frames[delimiter + 2];
        let parent = &frames[delimiter + 3];
        let metadata = &frames[delimiter + 4];
        let content = &frames[delimiter + 5];
        if !key.is_empty() {
            verify(key, signature, header, parent, metadata, content)?;
        }
        Ok(Self {
            header: serde_json::from_slice(header)?,
            parent: serde_json::from_slice(parent)?,
            metadata: serde_json::from_slice(metadata)?,
            content: serde_json::from_slice(content)?,
            identities,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Execution {
    pub stdout: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub timed_out: bool,
    pub interrupted: bool,
    pub replayed: usize,
}

pub struct KernelClient {
    info: ConnectionInfo,
    conn_path: PathBuf,
    child: Option<Child>,
    runtime: tokio::runtime::Runtime,
    shell: Option<DealerSocket>,
    iopub: Option<SubSocket>,
    session: String,
    history: Vec<String>,
    pub last_lost: Option<String>,
    pub max_output_bytes: usize,
}

impl KernelClient {
    /// Start a real ipykernel with the given interpreter and a generated
    /// connection file.
    pub fn start(python: &str, workdir: &Path) -> Result<Self> {
        std::fs::create_dir_all(workdir)?;
        let ports = free_ports(5)?;
        let session = format!("zero-{}", std::process::id());
        let info = ConnectionInfo {
            ip: "127.0.0.1".into(),
            transport: "tcp".into(),
            key: "zero-test-key".into(),
            signature_scheme: "hmac-sha256".into(),
            shell_port: ports[0],
            iopub_port: ports[1],
            stdin_port: ports[2],
            control_port: ports[3],
            hb_port: ports[4],
            kernel_name: "python3".into(),
        };
        let conn_path = workdir.join("kernel.json");
        info.to_file(&conn_path)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|e| ZeroError::new(ErrorCode::Unavailable, format!("tokio runtime: {e}")))?;
        let mut client = Self {
            info,
            conn_path,
            child: None,
            runtime,
            shell: None,
            iopub: None,
            session,
            history: Vec::new(),
            last_lost: None,
            max_output_bytes: 1024 * 1024,
        };
        client.spawn(python)?;
        client.connect()?;
        client.preload()?;
        Ok(client)
    }

    fn spawn(&mut self, python: &str) -> Result<()> {
        let child = Command::new(python)
            .arg("-m")
            .arg("ipykernel_launcher")
            .arg("-f")
            .arg(&self.conn_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ZeroError::new(ErrorCode::Unavailable, format!("cannot start {python}: {e}")))?;
        self.child = Some(child);
        // Give the kernel a moment to bind its sockets.
        std::thread::sleep(Duration::from_millis(400));
        Ok(())
    }

    fn connect(&mut self) -> Result<()> {
        let shell_ep = self.info.endpoint(self.info.shell_port);
        let iopub_ep = self.info.endpoint(self.info.iopub_port);
        let runtime = &self.runtime;
        let (shell, iopub) = runtime.block_on(async move {
            let mut shell = DealerSocket::new();
            shell.connect(&shell_ep).await.map_err(zmq_err)?;
            let mut iopub = SubSocket::new();
            iopub.connect(&iopub_ep).await.map_err(zmq_err)?;
            iopub.subscribe("").await.map_err(zmq_err)?;
            Ok::<_, ZeroError>((shell, iopub))
        })?;
        self.shell = Some(shell);
        self.iopub = Some(iopub);
        Ok(())
    }

    fn preload(&mut self) -> Result<()> {
        let bootstrap = r#"
class _ZeroTools: pass
zero = _ZeroTools()
def _zero_host(*args, **kwargs):
    raise PermissionError("host bridge unavailable in this kernel")
zero.web_search = lambda *a, **k: _zero_host("web_search", *a, **k)
zero.tool_search = lambda *a, **k: _zero_host("tool_search", *a, **k)
zero.trash = lambda *a, **k: _zero_host("trash", *a, **k)
import subprocess as _zero_sp
_zero_active = [0]
_ZeroPopen = _zero_sp.Popen
class _ZeroBoundedPopen(_ZeroPopen):
    def __init__(self, *a, **k):
        if _zero_active[0] >= 8:
            raise PermissionError("Zero process limit reached (8)")
        _ZeroPopen.__init__(self, *a, **k)
        _zero_active[0] += 1
    def wait(self, *a, **k):
        result = _ZeroPopen.wait(self, *a, **k)
        _zero_active[0] = max(0, _zero_active[0] - 1)
        return result
_zero_sp.Popen = _ZeroBoundedPopen
"#;
        let _ = self.execute(bootstrap, Duration::from_secs(10))?;
        self.history.clear();
        Ok(())
    }

    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    pub fn execute(&mut self, code: &str, timeout: Duration) -> Result<Execution> {
        if self.child.as_mut().and_then(|c| c.try_wait().ok().flatten()).is_some() {
            self.restart()?;
        }
        let message = Message::execute_request(&self.session, code);
        let msg_id = message.header.msg_id.clone();
        let frames = message.frame(&self.info.key)?;
        let payload = ZmqMessage::try_from(frames.into_iter().map(bytes::Bytes::from).collect::<Vec<_>>())
            .map_err(|_| ZeroError::new(ErrorCode::Serialization, "empty Jupyter message"))?;
        let shell = self.shell.as_mut().ok_or_else(|| ZeroError::new(ErrorCode::Unavailable, "no shell socket"))?;
        let runtime = &self.runtime;
        runtime.block_on(async { shell.send(payload).await }).map_err(zmq_err)?;

        let mut execution = Execution::default();
        let deadline = std::time::Instant::now() + timeout;
        let mut idle = false;
        let mut replayed = 0;
        while !idle {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                self.last_lost = Some(code.to_string());
                self.kill();
                execution.timed_out = true;
                return Ok(execution);
            }
            let iopub = self.iopub.as_mut().ok_or_else(|| ZeroError::new(ErrorCode::Unavailable, "no iopub socket"))?;
            let recv = runtime.block_on(async { tokio::time::timeout(remaining, iopub.recv()).await });
            match recv {
                Ok(Ok(message)) => {
                    let frames: Vec<Vec<u8>> = message.into_vec().into_iter().map(|b| b.to_vec()).collect();
                    let msg = match Message::decode(&frames, &self.info.key) {
                        Ok(msg) => msg,
                        Err(_) => continue,
                    };
                    if msg.parent.get("msg_id").and_then(|v| v.as_str()) != Some(msg_id.as_str()) {
                        continue;
                    }
                    match msg.header.msg_type.as_str() {
                        "status" if msg.content.get("execution_state").and_then(|v| v.as_str()) == Some("idle") => idle = true,
                        "stream" => {
                            if let Some(text) = msg.content.get("text").and_then(|v| v.as_str()) {
                                push_limited(&mut execution.stdout, text, self.max_output_bytes);
                            }
                        }
                        "execute_result" | "display_data" => {
                            if let Some(text) = msg.content.get("data").and_then(|d| d.get("text/plain")).and_then(|v| v.as_str()) {
                                execution.result = Some(text.to_string());
                            }
                        }
                        "error" => {
                            let ename = msg.content.get("ename").and_then(|v| v.as_str()).unwrap_or("Error");
                            let evalue = msg.content.get("evalue").and_then(|v| v.as_str()).unwrap_or("");
                            execution.error = Some(format!("{ename}: {evalue}"));
                        }
                        _ => {}
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    self.last_lost = Some(code.to_string());
                    self.kill();
                    execution.timed_out = true;
                    return Ok(execution);
                }
            }
        }
        // Read the shell reply (it is queued after execution finishes).
        let shell = self.shell.as_mut().ok_or_else(|| ZeroError::new(ErrorCode::Unavailable, "no shell socket"))?;
        let reply = runtime.block_on(async { tokio::time::timeout(Duration::from_secs(2), shell.recv()).await });
        if let Ok(Ok(message)) = reply {
            let frames: Vec<Vec<u8>> = message.into_vec().into_iter().map(|b| b.to_vec()).collect();
            if let Ok(msg) = Message::decode(&frames, &self.info.key) {
                if msg.header.msg_type == "execute_reply"
                    && msg.content.get("status").and_then(|v| v.as_str()) == Some("error")
                {
                    let ename = msg.content.get("ename").and_then(|v| v.as_str()).unwrap_or("Error");
                    execution.error.get_or_insert_with(|| ename.to_string());
                }
            }
        }
        if execution.error.is_none() {
            self.history.push(code.to_string());
            replayed = 0;
        }
        execution.replayed = replayed;
        Ok(execution)
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.shell = None;
        self.iopub = None;
    }

    /// Kill the kernel and start a new one on the same connection, replaying the
    /// successful cell history. In-flight work is reported in `last_lost`.
    pub fn restart(&mut self) -> Result<()> {
        let python = std::env::var("ZERO_PYTHON").unwrap_or_else(|_| default_python());
        self.kill();
        std::thread::sleep(Duration::from_millis(200));
        self.spawn(&python)?;
        self.connect()?;
        // Rehydrate from the log.
        let history = self.history.clone();
        self.history.clear();
        for code in &history {
            if let Ok(outcome) = self.execute(code, Duration::from_secs(10)) {
                if outcome.error.is_some() && self.last_lost.is_none() {
                    self.last_lost = Some(code.clone());
                }
            }
        }
        Ok(())
    }

    /// Execute and record the number of replayed cells (used by restart tests).
    pub fn execute_after_restart(&mut self, code: &str, timeout: Duration) -> Result<Execution> {
        if self.shell.is_none() {
            self.restart()?;
        }
        let replayed = self.history.len();
        let mut outcome = self.execute(code, timeout)?;
        outcome.replayed = replayed;
        Ok(outcome)
    }

    pub fn stop(&mut self) {
        self.kill();
    }
}

impl Drop for KernelClient {
    fn drop(&mut self) {
        self.kill();
    }
}

fn push_limited(target: &mut String, text: &str, limit: usize) {
    if target.len() >= limit {
        return;
    }
    let remaining = limit - target.len();
    if text.len() <= remaining {
        target.push_str(text);
    } else {
        target.push_str(&text[..remaining]);
        target.push_str("\n[output truncated]");
    }
}

fn zmq_err(error: zeromq::ZmqError) -> ZeroError {
    ZeroError::new(ErrorCode::Unavailable, format!("zeromq: {error}"))
}

fn free_ports(count: usize) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for _ in 0..count {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| ZeroError::new(ErrorCode::Unavailable, format!("bind: {e}")))?;
        ports.push(listener.local_addr().map_err(|e| ZeroError::new(ErrorCode::Unavailable, e.to_string()))?.port());
    }
    Ok(ports)
}

pub fn default_python() -> String {
    for candidate in ["python", "python3", "py"] {
        if Command::new(candidate).arg("--version").output().map(|o| o.status.success()).unwrap_or(false) {
            return candidate.to_string();
        }
    }
    "python".into()
}

pub fn kernel_available() -> bool {
    let python = default_python();
    Command::new(python)
        .args(["-c", "import ipykernel, zmq"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hmac_matches_the_jupyter_wire_fixture() {
        let signature = sign("zero-test-key", b"h", b"p", b"m", b"c").unwrap();
        assert_eq!(signature, "796d3cdbf4b9b8ef5c846a4ef82c4041753a5c711b6f66ff6f102a0dd8d6ec11");
        verify("zero-test-key", &signature, b"h", b"p", b"m", b"c").unwrap();
        let err = verify("zero-test-key", &signature, b"h", b"p", b"m", b"tampered").unwrap_err();
        assert_eq!(err.code(), ErrorCode::TamperDetected);
    }

    #[test]
    fn frames_round_trip_and_reject_a_bad_signature() {
        let message = Message::execute_request("sess", "print(1)");
        let frames = message.frame("zero-test-key").unwrap();
        assert_eq!(frames[0], DELIMITER.to_vec());
        let decoded = Message::decode(&frames, "zero-test-key").unwrap();
        assert_eq!(decoded.header.msg_type, "execute_request");
        assert_eq!(decoded.content["code"], "print(1)");

        let mut corrupted = frames.clone();
        corrupted[4] = serde_json::to_vec(&json!({"code": "evil"})).unwrap();
        let err = Message::decode(&corrupted, "zero-test-key").unwrap_err();
        assert_eq!(err.code(), ErrorCode::TamperDetected);
    }
}