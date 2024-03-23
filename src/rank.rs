use std::{cmp::min, collections::HashMap, fmt};
use serde::ser::SerializeSeq;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rank<T>
where
    T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
{
    rank: HashMap<T, usize>,
    size: usize,
}

impl<T> Rank<T>
where
    T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
{
    pub fn new(size_in: usize) -> Rank<T> {
        let r = Rank {
            size: size_in,
            rank: HashMap::with_capacity(size_in),
        };
        return r;
    }

    pub fn remove_lowest(&mut self) -> usize {
        let mut mink = &T::default();
        let mut minv: usize = 0;
        let mut maxv: usize = 0;

        for (k, v) in self.rank.iter() {
            if minv == 0 || *v < minv {
                minv = *v;
                mink = k;
            }
            if *v > maxv {
                maxv = *v;
            }
        }
        if minv > 0 {
            //println!("Removinng {} {} {} ", mink, minv, maxv);
            let Some((_k, _v)) = self.rank.remove_entry(&mink.clone()) else {
                return 0;
            };
            //println!("Removed: {} {} ", k, v);
        }
        return (2 * minv + maxv) / 3;
    }

    pub fn add(&mut self, element: T) {
        if self.rank.contains_key(&element) {
            let _c = self.rank.entry(element).and_modify(|v| *v += 1);
        } else {
            let mut val = 1;
            if self.rank.len() >= self.size {
                val = min(self.remove_lowest(), 1);
            }
            self.rank.insert(element, val);
        }
    }
}

impl<T> fmt::Display for Rank<T>
where
    T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut l = Vec::new();
        for (k, v) in self.rank.iter() {
            l.push((k, v));
        }
        l.sort_by(|a, b| (b.1).partial_cmp(a.1).unwrap());
        for (k, v) in l.iter() {
            write!(f, "{}: {}\n", k, v).expect("Cannot write output format ");
        }
        return write!(f, "");
    }
}

impl<T> Serialize for Rank<T>
where
    T: std::cmp::Eq + std::hash::Hash + std::fmt::Display + serde::Serialize + Default + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut l = Vec::new();
        for (k, v) in self.rank.iter() {
            l.push((k, v));
        }
        l.sort_by(|a, b| (b.1).partial_cmp(a.1).unwrap());
        let mut seq = serializer.serialize_seq(Some(l.len()))?;
        for i in l {
            seq.serialize_element(&format!("{} {}", &i.0, i.1))?;
        }
        return seq.end();
    }
}
