use std::{fs::File, io::Read};

use regex::Regex;


pub fn read_skip_list(filename: &str) -> Vec<Regex> {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(_) => {
            log::error!("Skip file not found: {}", filename);
            return Vec::new();
        }
    };
    let mut file_contents = String::new();
    match file.read_to_string(&mut file_contents) {
        //   .ok() {
        Ok(_) => {
            let lines: Vec<Regex> = file_contents
                .split("\n")
                .map(|s: &str| s.trim().to_string())
                .filter(|s| s != "")
                .map(|s| Regex::new(s.as_str()).unwrap())
                .collect();
            return lines;
        }
        Err(_) => {
            log::error!("File could not be read {}", filename);
            return Vec::new();
        }
    };
}