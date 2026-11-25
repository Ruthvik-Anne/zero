//! DEL-04 evidence: every listed Python deletion call raises `DeletionBlocked`.

use std::path::PathBuf;
use std::process::Command;

fn python() -> Option<&'static str> {
    ["python", "python3", "py"].into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

const SCRIPT: &str = r#"
import os, shutil, pathlib, tempfile
d = tempfile.mkdtemp()  # tempfile probes deletion; create it before installing the guard
from zero_guard import install, DeletionBlocked
install()
blocked = 0

def newfile(name, content="x"):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(content)
    return p

def expect(fn):
    global blocked
    try:
        fn()
    except DeletionBlocked:
        blocked += 1
        return
    raise SystemExit("NOT BLOCKED")

expect(lambda: os.remove(newfile("a")))
expect(lambda: os.unlink(newfile("b")))
dir1 = os.path.join(d, "dir1"); os.mkdir(dir1)
expect(lambda: os.rmdir(dir1))
nested = os.path.join(d, "n1", "n2"); os.makedirs(nested)
expect(lambda: os.removedirs(nested))
f = newfile("c")
expect(lambda: os.truncate(f, 0))
tree = os.path.join(d, "tree"); os.makedirs(os.path.join(tree, "sub"))
newfile(os.path.join("tree", "sub", "leaf"))
expect(lambda: shutil.rmtree(tree))
expect(lambda: pathlib.Path(newfile("d")).unlink())
pdir = pathlib.Path(os.path.join(d, "pdir")); pdir.mkdir()
expect(lambda: pdir.rmdir())
dst = newfile("dst")
expect(lambda: os.replace(newfile("src"), dst))
expect(lambda: shutil.move(newfile("src2"), dst))

# A rename to a fresh path is not a deletion and must still work.
src3 = newfile("src3")
os.rename(src3, os.path.join(d, "src3-new"))
assert os.path.exists(os.path.join(d, "src3-new"))
print("ALL_BLOCKED", blocked)
"#;

#[test]
fn every_listed_python_deletion_raises_deletion_blocked() {
    let Some(python) = python() else {
        println!("skipped: no python interpreter on PATH");
        return;
    };
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new(python)
        .arg("-c")
        .arg(SCRIPT)
        .env("PYTHONPATH", repo.join("python"))
        .output()
        .expect("run python");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "python guard failed: {stdout}\n{stderr}"
    );
    assert!(stdout.contains("ALL_BLOCKED 10"), "{stdout}{stderr}");
}
