use std::fs;
use std::path::PathBuf;

use pact_ref_core::{ContractCard, RefBindings, ReferenceForm};

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

#[test]
fn contract_card_examples_validate() {
    let dir = examples_dir().join("contracts");
    let mut checked = 0;
    for entry in fs::read_dir(&dir).expect("contracts dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read card");
        let card: ContractCard =
            serde_yaml::from_str(&text).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        card.validate()
            .unwrap_or_else(|error| panic!("{path:?}: {error}"));
        checked += 1;
    }
    assert_eq!(checked, 2, "expected two contract card examples");
}

#[test]
fn ref_bindings_example_validates_and_matches() {
    let path = examples_dir().join("bindings/se_lifecycle.refs.yaml");
    let text = fs::read_to_string(path).expect("read bindings");
    let bindings: RefBindings = serde_yaml::from_str(&text).expect("bindings");
    bindings.validate().expect("valid bindings");

    let reference =
        ReferenceForm::classify(Some("https://artifacts.example.com/se/design#sha256=abc"))
            .expect("reference");
    let matched = bindings
        .resolve(None, "design", &reference)
        .expect("design binding");
    assert_eq!(matched.rule.contract.as_deref(), Some("se/design-review@2"));
}
