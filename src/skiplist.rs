use regex::Regex;
use std::{fs::File, io::Read};

fn prefix_str(mut s1: String, s2: &str) -> String {
    s1.insert_str(0, s2);
    s1
}

fn parse_skiplist(file_contents: &str) -> Vec<Regex> {
    let lines: Vec<Regex> = file_contents
        .split('\n')
        .map(|s: &str| s.trim().to_string()) // .insert_str(0,"(?i)"))
        .filter(|s| !s.is_empty())
        .map(|t| prefix_str(t, "(?i)"))
        .map(|s| Regex::new(s.as_str()).unwrap())
        .collect();
    tracing::debug!("Regex: {lines:?}");
    lines
}

pub fn read_skip_list(filename: &str) -> Vec<Regex> {
    if filename.is_empty() {
        tracing::debug!("Empty skiplist");
        return Vec::new();
    }

    let Ok(mut file) = File::open(filename) else {
        tracing::error!("Skip file not found: {filename}");
        return Vec::new();
    };

    let mut file_contents = String::new();

    if file.read_to_string(&mut file_contents).is_ok() {
        parse_skiplist(&file_contents)
    } else {
        tracing::error!("File could not be read {filename}");
        return Vec::new();
    }
}

#[must_use]
pub fn match_skip_list(name: &str, skip_list: &[Regex]) -> bool {
    for i in skip_list {
        let r = i;
        if r.is_match(name.trim_end_matches('.')) {
            return true;
        }
    }
    false
}
#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::match_skip_list;
    use crate::skiplist::parse_skiplist;

    #[test]
    fn test_skiplist() {
        let binding = parse_skiplist(
            r".*\.nu\.nl$
            .*\.fritz\.box$
                
        ",
        );
        let sk: Vec<_> = binding.iter().map(|s| s.as_str()).collect();

        assert_eq!(
            sk,
            vec!(
                Regex::new(r"(?i).*\.nu\.nl$").unwrap().as_str(),
                Regex::new(r"(?i).*\.fritz\.box$").unwrap().as_str()
            )
        );
    }
    #[test]
    fn test_skiplist1() {
        let skip_list = parse_skiplist(
            r".*\.nu\.nl$
        .*\.fritz.box$
        
        ",
        );
        println!("{:?}", skip_list);
        assert!(match_skip_list("www.nu.nl", &skip_list));
        assert!(match_skip_list("www.tweakers.nl.fritz.box", &skip_list));
        assert!(match_skip_list("www.tweakers.nl.frITz.bOx", &skip_list));
        assert!(match_skip_list("www.tweakers.nl.frITz.bOx.", &skip_list));
        assert!(!match_skip_list("www.tweakers.nl", &skip_list));
        assert!(!match_skip_list("nu.nl", &skip_list));
        // assert_eq!(DNS_Class::find(4).unwrap(), DNS_Class::HS);
    }
}
