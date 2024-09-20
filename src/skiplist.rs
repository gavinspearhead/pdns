use regex::Regex;
use std::{fs::File, io::Read};

fn prefix_str(mut s1: String, s2: &str) -> String {
    s1.insert_str(0, s2);
    s1
}

pub(crate) struct Skip_List {
    entries: Vec<Regex>,
}

impl Skip_List {
    pub fn new() -> Skip_List {
        Skip_List {
            entries: Vec::new(),
        }
    }

    pub fn parse_skiplist(&mut self, file_contents: &str) {
        let lines: Vec<Regex> = file_contents
            .split('\n')
            .map(|s: &str| s.trim().to_string()) // .insert_str(0,"(?i)"))
            .filter(|s| !s.is_empty())
            .map(|t| prefix_str(t, "(?i)"))
            .map(|s| Regex::new(s.as_str()).unwrap())
            .collect();
        tracing::debug!("Regex: {lines:?}");
        self.entries = lines;
    }

    pub fn read_skip_list(&mut self, filename: &str) {
        if filename.is_empty() {
            tracing::debug!("Empty skiplist");
            self.entries = Vec::new();
            return;
        }

        let Ok(mut file) = File::open(filename) else {
            tracing::error!("Skip file not found: {filename}");
            self.entries = Vec::new();
            return;
        };

        let mut file_contents = String::new();

        if file.read_to_string(&mut file_contents).is_ok() {
            self.parse_skiplist(&file_contents)
        } else {
            tracing::error!("File could not be read {filename}");
            self.entries = Vec::new();
        }
    }

    #[must_use]
    pub fn match_skip_list(&self, name: &str) -> bool {
        for i in &self.entries {
            let r = i;
            if r.is_match(name.trim_end_matches('.')) {
                return true;
            }
        }
        false
    }
}
#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::skiplist::Skip_List;

    #[test]
    fn test_skiplist() {
        let mut sk = Skip_List::new();
        sk.parse_skiplist(
            r".*\.nu\.nl$
            .*\.fritz\.box$
                
        ",
        );
        let sk: Vec<_> = sk.entries.iter().map(|s| s.as_str()).collect();

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
        let mut skip_list = Skip_List::new();
        skip_list.parse_skiplist(
            r".*\.nu\.nl$
        .*\.fritz.box$
        
        ",
        );
        println!("{:?}", skip_list.entries);
        assert!(skip_list.match_skip_list("www.nu.nl"));
        assert!(skip_list.match_skip_list("www.tweakers.nl.fritz.box"));
        assert!(skip_list.match_skip_list("www.tweakers.nl.frITz.bOx"));
        assert!(skip_list.match_skip_list("www.tweakers.nl.frITz.bOx."));
        assert!(!skip_list.match_skip_list("www.tweakers.nl"));
        assert!(!skip_list.match_skip_list("nu.nl"));
        // assert_eq!(DNS_Class::find(4).unwrap(), DNS_Class::HS);
    }
}
