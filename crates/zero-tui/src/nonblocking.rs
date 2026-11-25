//! Non-blocking loops (TUI-15): render and input never wait on I/O. The input
//! pump is a channel; render jobs run on worker threads and report back.

use crate::input::Event;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

pub struct InputPump {
    tx: Sender<Event>,
    rx: Receiver<Event>,
}

impl Default for InputPump {
    fn default() -> Self {
        Self::new()
    }
}

impl InputPump {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self { tx, rx }
    }

    pub fn sender(&self) -> Sender<Event> {
        self.tx.clone()
    }

    /// Never blocks on I/O: returns immediately with whatever is queued.
    pub fn drain(&self, max: usize) -> Vec<Event> {
        let mut out = Vec::new();
        while out.len() < max {
            match self.rx.try_recv() {
                Ok(event) => out.push(event),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        out
    }

    pub fn push(&self, event: Event) {
        let _ = self.tx.send(event);
    }
}

/// A render job (a frame computation, a disk read, a provider wait) that runs on
/// its own thread and reports when finished.
pub fn spawn_stalled_job(duration: Duration) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(duration);
    })
}

/// Measure how long it takes to drain input while jobs are in flight.
pub fn measure_input_latency(pump: &InputPump, events: usize) -> (usize, Duration) {
    for i in 0..events {
        pump.push(Event::Key(crate::input::Key::plain(crate::input::KeyCode::Char(
            char::from(b'a' + (i % 26) as u8),
        ))));
    }
    let start = Instant::now();
    let drained = pump.drain(events).len();
    (drained, start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{Key, KeyCode, Event};

    #[test]
    fn stalled_disk_and_provider_keep_input_responsive() {
        let pump = InputPump::new();
        let disk = spawn_stalled_job(Duration::from_millis(800));
        let provider = spawn_stalled_job(Duration::from_millis(800));
        let start = Instant::now();

        let (count, latency) = measure_input_latency(&pump, 20);
        assert_eq!(count, 20, "all queued input is handled");
        assert!(
            latency < Duration::from_millis(150),
            "input latency {:?} must not wait for I/O",
            latency
        );
        assert!(start.elapsed() < Duration::from_millis(500), "input drained while jobs stalled");

        disk.join().unwrap();
        provider.join().unwrap();
        // A second drain after the jobs finish is still immediate.
        pump.push(Event::Key(Key::plain(KeyCode::Enter)));
        assert_eq!(pump.drain(1).len(), 1);
    }
}
