pub mod edr_detect_rules;
use once_cell::sync::Lazy;
use sigma_rust::Rule;
use std::fs;


fn load_rules(dir: &str) -> Vec<sigma_rust::Rule> {
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


pub static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    load_rules("rule")
});