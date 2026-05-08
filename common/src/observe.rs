//! Live observability for the TUI: byte/packet counters + an in-memory
//! tracing log ring.
//!
//! The pump loops increment [`PumpStats`] atomically; a TUI thread snapshots
//! them periodically. [`LogRing`] is a bounded ring buffer that doubles as a
//! `tracing_subscriber::fmt::MakeWriter`, so log lines can be diverted into
//! the TUI when stdout is unavailable.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

#[derive(Default, Debug)]
pub struct PumpStats {
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
}

impl PumpStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_rx(&self, bytes: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct StatsSnapshot {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

/// Client-side connection state for the TUI status panel.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnState {
    Idle = 0,
    Connecting = 1,
    Handshaking = 2,
    Connected = 3,
    Disconnected = 4,
}

impl ConnState {
    pub fn label(self) -> &'static str {
        match self {
            ConnState::Idle => "idle",
            ConnState::Connecting => "connecting",
            ConnState::Handshaking => "handshaking",
            ConnState::Connected => "connected",
            ConnState::Disconnected => "disconnected",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => ConnState::Connecting,
            2 => ConnState::Handshaking,
            3 => ConnState::Connected,
            4 => ConnState::Disconnected,
            _ => ConnState::Idle,
        }
    }
}

#[derive(Default, Debug)]
pub struct ConnStatus {
    state: AtomicU64,
}

impl ConnStatus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set(&self, s: ConnState) {
        self.state.store(s as u64, Ordering::Relaxed);
    }

    pub fn get(&self) -> ConnState {
        ConnState::from_u8(self.state.load(Ordering::Relaxed) as u8)
    }
}

#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<VecDeque<String>>>,
    capacity: usize,
}

impl LogRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&self, line: String) {
        let mut g = self.inner.lock().expect("LogRing mutex poisoned");
        if g.len() >= self.capacity {
            g.pop_front();
        }
        g.push_back(line);
    }

    /// Return the most-recent `n` lines, oldest first.
    pub fn snapshot(&self, n: usize) -> Vec<String> {
        let g = self.inner.lock().expect("LogRing mutex poisoned");
        let len = g.len();
        let start = len.saturating_sub(n);
        g.iter().skip(start).cloned().collect()
    }

    pub fn writer(&self) -> LogMaker {
        LogMaker { ring: self.clone() }
    }
}

/// MakeWriter wrapper around a [`LogRing`]. Each event allocates a small
/// scratch buffer; on drop, complete `\n`-terminated lines are pushed.
pub struct LogMaker {
    ring: LogRing,
}

pub struct LogLineWriter {
    ring: LogRing,
    scratch: Vec<u8>,
}

impl io::Write for LogLineWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.scratch.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogLineWriter {
    fn drop(&mut self) {
        if self.scratch.is_empty() {
            return;
        }
        let s = String::from_utf8_lossy(&self.scratch);
        for line in s.lines() {
            if !line.is_empty() {
                self.ring.push(line.to_owned());
            }
        }
    }
}

impl<'a> MakeWriter<'a> for LogMaker {
    type Writer = LogLineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogLineWriter {
            ring: self.ring.clone(),
            scratch: Vec::with_capacity(256),
        }
    }
}

/// Format a byte count in a human-friendly base-1024 form.
pub fn fmt_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", b, UNITS[i])
    } else {
        format!("{:.2} {}", v, UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn pump_stats_record() {
        let s = PumpStats::default();
        s.record_tx(100);
        s.record_tx(50);
        s.record_rx(200);
        let snap = s.snapshot();
        assert_eq!(snap.tx_packets, 2);
        assert_eq!(snap.tx_bytes, 150);
        assert_eq!(snap.rx_packets, 1);
        assert_eq!(snap.rx_bytes, 200);
    }

    #[test]
    fn log_ring_caps_capacity() {
        let r = LogRing::new(3);
        for i in 0..10 {
            r.push(format!("line {i}"));
        }
        let lines = r.snapshot(10);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line 7");
        assert_eq!(lines[2], "line 9");
    }

    #[test]
    fn log_writer_drop_pushes_lines() {
        let r = LogRing::new(8);
        let maker = r.writer();
        {
            let mut w = maker.make_writer();
            w.write_all(b"hello\nworld\n").unwrap();
        }
        let lines = r.snapshot(8);
        assert_eq!(lines, vec!["hello".to_owned(), "world".to_owned()]);
    }

    #[test]
    fn fmt_bytes_units() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.00 KiB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.00 MiB");
    }
}
