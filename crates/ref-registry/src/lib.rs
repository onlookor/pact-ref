//! 可选发现：按引用查 ContractCard 投影。
//!
//! 注册表只做发现，不做真相源；没有注册表时，RefBindings 仍可本地匹配。

use std::collections::HashMap;

use pact_ref_core::{ContractDescriptor, ReferenceError, ReferenceForm, Registry};

/// 内存实现，供引导阶段和测试使用。
pub struct MemoryRegistry {
    entries: HashMap<String, ContractDescriptor>,
}

impl MemoryRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, reference: impl Into<String>, descriptor: ContractDescriptor) {
        self.entries.insert(reference.into(), descriptor);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for MemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry for MemoryRegistry {
    fn describe(&self, reference: &ReferenceForm) -> Result<ContractDescriptor, ReferenceError> {
        let key = reference
            .as_str()
            .ok_or_else(|| ReferenceError::NotFound("∅".to_owned()))?;
        self.entries
            .get(key)
            .cloned()
            .ok_or_else(|| ReferenceError::NotFound(key.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryRegistry;
    use pact_ref_core::{ContractDescriptor, ReferenceError, ReferenceForm, Registry};

    fn descriptor() -> ContractDescriptor {
        ContractDescriptor {
            contract_id: "demo/artifact".to_owned(),
            version: "1".to_owned(),
            media_type: "application/octet-stream".to_owned(),
        }
    }

    #[test]
    fn describes_registered_reference() {
        let mut registry = MemoryRegistry::new();
        registry.insert("https://example.com/a", descriptor());
        let reference = ReferenceForm::classify(Some("https://example.com/a")).expect("reference");
        let described = registry.describe(&reference).expect("describe");
        assert_eq!(described.contract_id, "demo/artifact");
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
    }

    #[test]
    fn reports_missing_reference() {
        let registry = MemoryRegistry::new();
        let reference =
            ReferenceForm::classify(Some("https://example.com/missing")).expect("reference");
        let error = registry.describe(&reference).expect_err("must fail");
        assert!(matches!(error, ReferenceError::NotFound(_)));
        assert!(registry.is_empty());
    }
}
