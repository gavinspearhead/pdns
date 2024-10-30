use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Serialize, Deserialize, Debug, Clone)]

pub(crate) struct Bucket {
    items: Vec<u64>,
    last_post: usize,
    last_group: usize,
}

impl Bucket {
    fn new(size: usize) -> Bucket {
        Bucket {
            items: vec![0; size],
            last_post: 0,
            last_group: 0,
        }
    }

    fn add(&mut self, position: u32, count: u64, group_val: u32) {
        let pos = position as usize;
        let len = self.items.len();
        if pos >= len {
            debug!("Cannot update item");
            return;
        }
        let group = group_val as usize;

        if pos == self.last_post && group == self.last_group {
            self.items[pos] += count;
        } else if group == self.last_group {
            if pos > self.last_post {
                /*                for i in self.last_post + 1..pos {
                    self.items[i] = 0;
                }*/
                self.items[self.last_post + 1..pos].fill(0);
            } else {
                /*                for i in 0..pos {
                    self.items[i] = 0;
                }*/
                self.items[0..pos].fill(0);
            }
            self.items[pos] = count;
        } else if group == self.last_group + 1 {
            self.items[self.last_post + 1..len].fill(0);
            /*
                for i in self.last_post + 1..self.items.len() {
                self.items[i] = 0;
            }*/
            self.items[0..pos].fill(0);
            /*for i in 0..pos {
                self.items[i] = 0;
            }*/
            self.items[pos] = count;
        } else {
            self.items = vec![0; len];
            self.items[pos] = count;
        }
        self.last_post = pos;
        self.last_group = group;
    }
}

#[cfg(test)]
mod tests {
    use super::Bucket;
    #[test]
    fn test_bucket() {
        let mut hour = Bucket::new(12);
        let mut v = vec![0; 12];

        hour.add(1, 1, 1);
        hour.add(1, 1, 1);
        v[1] = 2;
        assert_eq!(hour.items, v);
        hour.add(2, 1, 1);
        hour.add(3, 1, 1);
        // println!("{} {}", hour.last_post, hour.last_group);
        v[1] = 2;
        v[2] = 1;
        v[3] = 1;
        assert_eq!(hour.items, v);
        hour.add(10, 1, 1);
        //println!("{} {}", hour.last_post, hour.last_group);
        v[10] = 1;
        assert_eq!(hour.items, v);
        hour.add(3, 1, 2);
        // println!("{} {}", hour.last_post, hour.last_group);
        v[1] = 0;
        v[2] = 0;
        v[3] = 1;
        assert_eq!(hour.items, v);
        hour.add(4, 1, 2);
        v[4] = 1;
        assert_eq!(hour.items, v);
        // println!("{} {}", hour.last_post, hour.last_group);
        hour.add(2, 1, 4);
        hour.add(6, 1, 4);
        hour.add(16, 1, 4);
        v = vec![0; 12];
        v[2] = 1;
        v[6] = 1;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Time_stats {
    per_month: Bucket,
    per_minute: Bucket,
    per_hour: Bucket,
    per_day: Bucket,
    // per_second: Bucket,
}

impl Time_stats {
    pub(crate) fn new() -> Time_stats {
        Time_stats {
            per_minute: Bucket::new(60),
            per_hour: Bucket::new(24),
            per_day: Bucket::new(31),
            per_month: Bucket::new(12),
        }
    }

    pub(crate) fn add(&mut self, time_stamp: DateTime<Utc>, count: u64) {
        let m = time_stamp.minute();
        let h = time_stamp.hour();
        let d = time_stamp.day() - 1; //correct because start at 1
        let mon = time_stamp.month() - 1;
        let year = time_stamp.year() as u32;
        self.per_month.add(mon, count, year);
        self.per_day.add(d, count, mon);
        self.per_minute.add(m, count, h);
        self.per_hour.add(h, count, d);
    }
}
