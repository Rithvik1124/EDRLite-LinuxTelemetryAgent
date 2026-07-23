use std::fs;
use serde_json::{json,Value};
use std::io::Read;
//use std::io::prelude::*;
use crate::detect::{SIGMA_RULES, YARA_RULES};
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};
use yara_x;
// use yaml_rust::yaml::{Hash, Yaml};
// use yaml_rust::YamlLoader;

#[warn(unused_variables)]

pub fn match_yara_rule(file_dir: &str, rules: yara_x::Rules ){
    let mut file = fs::File::open(file_dir).unwrap();    
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    println!("Contents:{:?}",data);
    let mut scanner = yara_x::Scanner::new(&rules);

    let results = scanner.scan(&data).unwrap();

    // Scan some data.
    //let results = scanner.scan(contents.as_bytes()).unwrap();

    if results.matching_rules().len() == 1{
        println!("Matches");
    }
}

pub fn match_sigma_rule(event: &Event) {
    for rule in SIGMA_RULES.iter() {
        if rule.is_match(event) {
            println!("MATCH: {}", rule.title);
        }
        else {
            println!("No event found match {:?}", &event)
        }
    }
}


