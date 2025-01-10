use core::cmp::Ordering::Equal;
use std::collections::HashMap;
use serde::{Serialize, Serializer};
use serde::ser::SerializeMap;

// For use with serde's [serialize_with] attribute
pub(crate) fn ordered_map<S, K: Ord + Serialize + ToString, V: Serialize + PartialOrd >(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut l: Vec<_> = value.iter().collect();
    l.sort_by(|a, b| a.0.to_string().partial_cmp(&b.0.to_string()).unwrap_or(Equal));

    let mut map = serializer.serialize_map(Some(l.len()))?;
    for i in l {
        map.serialize_entry(&i.0, i.1)?;
    }
    map.end()

}
