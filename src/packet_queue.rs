use crate::packet_info::Packet_info;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default)]
pub(crate) struct Packet_Queue {
    queue: Arc<Mutex<VecDeque<Option<Packet_info>>>>,
}

impl Packet_Queue {
    const INITIAL_QUEUE_SIZE: usize = 32;
    pub fn new() -> Packet_Queue {
        Packet_Queue {
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(
                Self::INITIAL_QUEUE_SIZE,
            ))),
        }
    }
    #[inline]
    pub fn push_back(&self, packet_info: Option<Packet_info>) {
        self.queue.lock().unwrap().push_back(packet_info);
    }
    #[inline]
    pub fn pop_front(&self) -> Option<Option<Packet_info>> {
        self.queue.lock().unwrap().pop_front()
    }
}
