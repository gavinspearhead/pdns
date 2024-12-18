use serde::ser::SerializeMap;
use serde::Serialize;
use std::cmp::Ordering::Equal;
use std::{cmp::min, collections::HashMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Default + Clone,
{
    rank: HashMap<T, usize>,
    size: usize,
}

impl<T> Default for Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Default + Clone,
{
    fn default() -> Self {
        Self {
            rank: HashMap::default(),
            size: Default::default(),
        }
    }
}

impl<T> Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Default + Clone,
{
    pub fn new(size_in: usize) -> Rank<T> {
        Rank {
            size: size_in,
            rank: HashMap::with_capacity(size_in),
        }
    }

    pub fn remove_lowest(&mut self) -> usize {
        let mut mink = None;
        let mut minv: usize = 0;
        let mut maxv: usize = 0;

        for (k, v) in &self.rank {
            if minv == 0 || *v < minv {
                minv = *v;
                mink = Some(k);
            }
            if *v > maxv {
                maxv = *v;
            }
        }
        if let Some(k) = mink {
            self.rank.remove(&k.clone());
            (2 * minv + maxv) / 3
        } else {
            0
        }
    }

    pub fn add(&mut self, element: &T) {
        if let Some(elem) = self.rank.get_mut(element) {
            *elem += 1;
        } else {
            let val = if self.rank.len() >= self.size {
                min(self.remove_lowest(), 1)
            } else {
                1
            };
            self.rank.insert(element.clone(), val);
        }
    }
}

impl<T> fmt::Display for Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Default + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut l = Vec::new();
        for (k, v) in &self.rank {
            l.push((k, v));
        }
        l.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(Equal));
        for (k, v) in &l {
            writeln!(f, "{k}: {v}").expect("Cannot write output format ");
        }
        write!(f, "")
    }
}

impl<T> Serialize for Rank<T>
where
    T: Eq + std::hash::Hash + fmt::Display + serde::Serialize + Default + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut l = Vec::new();
        for (k, v) in &self.rank {
            l.push((k, v));
        }
        l.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(Equal));

        let mut map = serializer.serialize_map(Some(l.len()))?;
        for i in l {
            map.serialize_entry(&i.0, i.1)?;
        }
        map.end()
    }
}
