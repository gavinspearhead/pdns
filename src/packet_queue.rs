use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use pcap::Linktype;

#[derive(Debug, Clone, Default)]
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
    pub fn push_back(&self, packet: Option<(Vec<u8>, DateTime<Utc>, Linktype)>) {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() < Self::MAX_QUEUE_SIZE {
            queue.push_back(packet);
        }
    }
    #[inline]
    pub fn pop_front(&self) -> Option<Option<(Vec<u8>, DateTime<Utc>, Linktype)>> {
        self.queue.lock().unwrap().pop_front()
    }
}
