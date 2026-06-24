use std::fs;
use serde_json::{json,Value};
//use std::io::prelude::*;
use crate::detect::RULES;
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};
// use yaml_rust::yaml::{Hash, Yaml};
// use yaml_rust::YamlLoader;

#[warn(unused_variables)]

/*
fn load_rules(dir: &str) -> Vec<sigma_rust::Rule> {
    let mut rules = Vec::new();

    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            let contents = fs::read_to_string(&path).unwrap();
            let rule = rule_from_yaml(&contents).unwrap();
            rules.push(rule);
        }
    }

    return rules
}*/




pub fn match_rule(event_json: &str) {
    //let mut file = File::open(file).expect("Unable to open file");
    //let mut contents = String::new();


    //file.read_to_string(&mut contents)
        //.expect("Unable to read file");

    //println!("\n\n Stuff{}\n\n", contents);
    //let rule = rule_from_yaml(&contents).unwrap();

    //let docs = YamlLoader::load_from_str(&contents).unwrap();

    // let event = event_from_json(r#"{"TargetFilename": "C:\\temp\\file.au3", "Image": "C:\\temp\\autoit4.exe", "Event": {"ID": 42}}"#,).unwrap();
    //let v: Value = sigma_rust::from_str(x).unwrap();
    let event = event_from_json(&serde_json::to_string(event_json).unwrap());
   
    /*let event = event_from_json(
        r#"{"TargetFilename": "C:\\temp\\file.au3", "Image": "C:\\temp\\autoit4.exe"}"#
    ).unwrap();*/

    match event {
    Ok(ev) => {
        println!("Got event");
        something(&ev);
    }
    Err(e) => {
        println!("Error: {:?}", e);
    }
    }

}


fn something(event: &Event) {
    for rule in RULES.iter() {
        if rule.is_match(event) {
            println!("MATCH: {}", rule.title);
        }
    }
}


