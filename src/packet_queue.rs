use chrono::{DateTime, Utc};
use pcap::Linktype;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub(crate) struct PacketQueue {
    queue: Arc<Mutex<VecDeque<Option<(Vec<u8>, DateTime<Utc>, Linktype)>>>>,
}

impl PacketQueue {
    const INITIAL_QUEUE_SIZE: usize = 32;
    const MAX_QUEUE_SIZE: usize = 1024;
    pub fn new() -> PacketQueue {
        PacketQueue {
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(
                Self::INITIAL_QUEUE_SIZE,
            ))),
        }
    }
    #[inline]
    pub fn push_back(&self, packet: Option<(Vec<u8>, DateTime<Utc>, Linktype)>) -> bool {
        let mut queue = self.queue.lock().unwrap_or_else(|poisoned| {
            // Clear the poison and recover the data
            poisoned.into_inner()
        });
        if queue.len() < Self::MAX_QUEUE_SIZE || packet == None {
            queue.push_back(packet);
            true
        } else {
            false
        }
    }
    #[inline]
    pub fn pop_front(&self) -> Option<Option<(Vec<u8>, DateTime<Utc>, Linktype)>> {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| {
                // Clear the poison and recover the data
                poisoned.into_inner()
            })
            .pop_front()
    }
}

impl Default for PacketQueue {
    fn default() -> Self {
        Self::new()
    }
}
