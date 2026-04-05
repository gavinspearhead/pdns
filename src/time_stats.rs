use chrono::{DateTime, Datelike as _, Timelike as _, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub(crate) struct Bucket {
    last_post: usize,
    last_group: usize,
    items: Vec<u128>,
}

impl Bucket {
    fn new(size: usize) -> Bucket {
        Bucket {
            items: vec![0; size],
            last_post: 0,
            last_group: 0,
        }
    }

    #[inline]
    fn get_item(&self) -> &Vec<u128> {
        self.items.as_ref()
    }
    fn add(&mut self, position: u32, count: u128, group_val: u32) {
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
                self.items[self.last_post + 1..pos].fill(0);
            } else {
                self.items[0..pos].fill(0);
            }
            self.items[pos] = count;
        } else if group == self.last_group + 1 {
            self.items[self.last_post + 1..len].fill(0);
            self.items[0..pos].fill(0);
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
    use super::*;
    use chrono::TimeZone;

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
        v[1] = 2;
        v[2] = 1;
        v[3] = 1;
        assert_eq!(hour.items, v);
        hour.add(10, 1, 1);
        v[10] = 1;
        assert_eq!(hour.items, v);
        hour.add(3, 1, 2);
        v[1] = 0;
        v[2] = 0;
        v[3] = 1;
        assert_eq!(hour.items, v);
        hour.add(4, 1, 2);
        v[4] = 1;
        assert_eq!(hour.items, v);
        hour.add(2, 1, 4);
        hour.add(6, 1, 4);
        hour.add(16, 1, 4);
        v = vec![0; 12];
        v[2] = 1;
        v[6] = 1;
    }

    #[test]
    fn test_time_stats_transitions() {
        let mut stats = Time_stats::new();

        // 1. Test Year Transition: Dec 31, 2024 23:59:59 -> Jan 1, 2025 00:00:00
        let t1 = Utc.with_ymd_and_hms(2024, 12, 31, 23, 59, 59).unwrap();
        let t2 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        stats.add(t1, 10);
        assert_eq!(stats.per_month.items[11], 10); // Dec
        assert_eq!(stats.per_day.items[30], 10); // 31st (day0 is 30)
        assert_eq!(stats.per_second.items[59], 10);

        stats.add(t2, 5);

        // After year change, per_month should have reset via 'group == last_group + 1'
        // Dec (index 11) should be 0, Jan (index 0) should be 5
        assert_eq!(stats.per_month.items[11], 0);
        assert_eq!(stats.per_month.items[0], 5);

        // per_day should have reset because month changed (even though year changed too)
        assert_eq!(stats.per_day.items[30], 0);
        assert_eq!(stats.per_day.items[0], 5);

        // 2. Test Day Transition: Jan 1st -> Jan 2nd
        let t3 = Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0).unwrap();
        stats.add(t3, 7);
        assert_eq!(stats.per_day.items[0], 0); // Jan 1st cleared
        assert_eq!(stats.per_day.items[1], 7); // Jan 2nd set
        assert_eq!(stats.per_hour.items[0], 7); // Hour 0 of new day

        // 3. Test skipping time (The 'else' block)
        // Move from Jan 2nd to Jan 5th (skipping 2 days)
        let t4 = Utc.with_ymd_and_hms(2025, 1, 5, 12, 0, 0).unwrap();
        stats.add(t4, 100);
        // Everything in per_day should be 0 except the new position
        assert_eq!(stats.per_day.items[1], 0);
        assert_eq!(stats.per_day.items[4], 100);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum STAT_ITEM {
    MONTH,
    MINUTE,
    HOUR,
    DAY,
    SECOND,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub(crate) struct Time_stats {
    pub(crate) per_month: Bucket,
    pub(crate) per_minute: Bucket,
    pub(crate) per_hour: Bucket,
    pub(crate) per_day: Bucket,
    pub(crate) per_second: Bucket,
}

impl Time_stats {
    pub(crate) fn new() -> Time_stats {
        Time_stats {
            per_minute: Bucket::new(60),
            per_hour: Bucket::new(24),
            per_day: Bucket::new(31),
            per_month: Bucket::new(12),
            per_second: Bucket::new(60),
        }
    }

    pub(crate) fn add(&mut self, time_stamp: DateTime<Utc>, count: u128) {
        let m = time_stamp.minute();
        let s = time_stamp.second();
        let h = time_stamp.hour();
        let d = time_stamp.day0();
        let mon = time_stamp.month0();
        let year = time_stamp.year() as u32;

        // Use absolute values for groups to handle wrap-arounds (like year changes)
        let total_months = (year * 12) + mon;
        let total_days = time_stamp.num_days_from_ce();
        let total_hours = (total_days as i64 * 24) + h as i64;
        let total_minutes = (total_hours * 60) + m as i64;

        self.per_month.add(mon, count, year);
        self.per_day.add(d, count, total_months);
        self.per_hour.add(h, count, total_days as u32);
        self.per_minute.add(m, count, total_hours as u32);
        self.per_second.add(s, count, total_minutes as u32);
    }

    pub(crate) fn get_item(&self, stat_item: &STAT_ITEM) -> &Vec<u128> {
        match stat_item {
            STAT_ITEM::MONTH => self.per_month.get_item(),
            STAT_ITEM::MINUTE => self.per_minute.get_item(),
            STAT_ITEM::HOUR => self.per_hour.get_item(),
            STAT_ITEM::DAY => self.per_day.get_item(),
            STAT_ITEM::SECOND => self.per_second.get_item(),
        }
    }
}
