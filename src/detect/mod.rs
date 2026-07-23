pub mod edr_detect_rules;
use once_cell::sync::Lazy;
use sigma_rust::Rule;
use std::fs;
//use std::iter::Scan;
use yara_x::{self, Scanner};
//use std::io::Read;


fn load_sigma_rules(dir: &str) -> Vec<sigma_rust::Rule> {
    let mut rules = Vec::new();

    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            let contents = fs::read_to_string(&path).unwrap();
            let rule = sigma_rust::rule_from_yaml(&contents).unwrap();
            rules.push(rule);
        }
    }

    return rules
}

pub fn load_yara_rules(yara_rules_dir: &str)-> yara_x::Rules{
    let mut compiler = yara_x::Compiler::new();
    compiler.add_include_dir(yara_rules_dir);

    for entry in fs::read_dir(yara_rules_dir).unwrap() {
        let entry = entry.unwrap(); // entry is now a DirEntry

        let source = std::fs::read_to_string(entry.path()).unwrap();
        compiler.add_source(source.as_str()).unwrap();
    }

    let rules = compiler.build();

    // Create a scanner that uses the compiled rules.
    //let scanner = yara_x::Scanner::new(&rules);
    rules


}


pub static YARA_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    load_sigma_rules("rules/yara/")
});

pub static SIGMA_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    load_sigma_rules("rules/sigma/")
});