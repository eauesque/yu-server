use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, RwLock,
};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub timestamp: f64,
    pub level: String,
    pub target: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Map<String, serde_json::Value>>,
}

pub struct PartialEntry {
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: Option<serde_json::Map<String, serde_json::Value>>,
}

pub const MAX_LOG_SSE_PER_IP: usize = 3;
const BROADCAST_CAPACITY: usize = 512;

pub struct LogRingBuffer {
    entries: RwLock<VecDeque<LogEntry>>,
    next_seq: AtomicU64,
    capacity: usize,
    pub(super) notify: broadcast::Sender<LogEntry>,
    connections: Mutex<HashMap<IpAddr, usize>>,
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub(crate) fn level_rank(l: &str) -> u8 {
    match l {
        "TRACE" => 0,
        "DEBUG" => 1,
        "INFO" => 2,
        "WARN" => 3,
        "ERROR" => 4,
        _ => 0,
    }
}

impl LogRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let (notify, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            entries: RwLock::new(VecDeque::with_capacity(capacity)),
            next_seq: AtomicU64::new(0),
            capacity,
            notify,
            connections: Mutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, partial: PartialEntry) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let entry = LogEntry {
            seq,
            timestamp: unix_now(),
            level: partial.level,
            target: partial.target,
            message: partial.message,
            fields: partial.fields,
        };
        {
            let mut ring = self.entries.write().unwrap();
            if ring.len() >= self.capacity {
                ring.pop_front();
            }
            ring.push_back(entry.clone());
        }
        let _ = self.notify.send(entry);
    }

    /// Return entries in ascending seq order (oldest first).
    pub fn recent(
        &self,
        limit: usize,
        min_level: Option<&str>,
        after_seq: Option<u64>,
    ) -> Vec<LogEntry> {
        let ring = self.entries.read().unwrap();
        let min_rank = min_level
            .map(|l| level_rank(&l.to_ascii_uppercase()))
            .unwrap_or(0);
        let mut out: Vec<LogEntry> = ring
            .iter()
            .filter(|e| after_seq.is_none_or(|s| e.seq > s) && level_rank(&e.level) >= min_rank)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        out.reverse();
        out
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.notify.subscribe()
    }

    pub fn register_connection(&self, ip: IpAddr) -> bool {
        let mut guard = self.connections.lock().unwrap();
        let count = guard.entry(ip).or_insert(0);
        if *count >= MAX_LOG_SSE_PER_IP {
            return false;
        }
        *count += 1;
        true
    }

    pub fn unregister_connection(&self, ip: IpAddr) {
        let mut guard = self.connections.lock().unwrap();
        if let Some(count) = guard.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.remove(&ip);
            }
        }
    }
}
