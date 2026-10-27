use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::SpecError;
use crate::reference::{PinningRequirement, ReferenceForm};
use crate::{
    is_valid_contract_id, is_valid_scheme, is_valid_scope_name, is_valid_sha256, API_VERSION,
    REF_BINDINGS_KIND,
};

/// 域旁的 RefBindings 清单。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefBindings {
    pub api_version: String,
    pub kind: String,
    pub metadata: BindingsMetadata,
    pub spec: BindingsSpec,
}

impl RefBindings {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            api_version: API_VERSION.to_owned(),
            kind: REF_BINDINGS_KIND.to_owned(),
            metadata: BindingsMetadata {
                domain: domain.into(),
                declaration_digest: None,
            },
            spec: BindingsSpec::default(),
        }
    }

    /// 结构/取值校验。调用方应在匹配前至少执行一次。
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.api_version != API_VERSION {
            return Err(SpecError::InvalidBindings(format!(
                "apiVersion must be {API_VERSION}"
            )));
        }
        if self.kind != REF_BINDINGS_KIND {
            return Err(SpecError::InvalidBindings(format!(
                "kind must be {REF_BINDINGS_KIND}"
            )));
        }
        if !is_valid_scope_name(&self.metadata.domain) {
            return Err(SpecError::InvalidDomain(self.metadata.domain.clone()));
        }
        if let Some(digest) = &self.metadata.declaration_digest {
            if !is_valid_sha256(digest) {
                return Err(SpecError::InvalidDigest(digest.clone()));
            }
        }

        if let Some(defaults) = &self.spec.defaults {
            validate_rule(&defaults.rule, "defaults")?;
        }
        for (type_name, binding) in &self.spec.types {
            if type_name.trim().is_empty() {
                return Err(SpecError::InvalidBindings(
                    "types contains an empty type name".to_owned(),
                ));
            }
            validate_rule(&binding.rule, type_name)?;
        }
        for (scheme, rule) in &self.spec.schemes {
            if !is_valid_scheme(scheme) {
                return Err(SpecError::InvalidScheme(scheme.clone()));
            }
            validate_rule(&rule.rule, scheme)?;
        }
        for (instance, bindings) in &self.spec.instances {
            if !is_valid_scope_name(instance) {
                return Err(SpecError::InvalidDomain(instance.clone()));
            }
            for (type_name, binding) in &bindings.types {
                if type_name.trim().is_empty() {
                    return Err(SpecError::InvalidBindings(format!(
                        "instance {instance} contains an empty type name"
                    )));
                }
                validate_rule(&binding.rule, type_name)?;
            }
        }
        Ok(())
    }

    /// 按 `defaults → scheme → type → instance/type` 的继承链求有效规则，并校验票面。
    ///
    /// `instance` 为 `None` 时只做域级匹配。
    pub fn resolve(
        &self,
        instance: Option<&str>,
        type_name: &str,
        reference: &ReferenceForm,
    ) -> Result<BindingMatch, SpecError> {
        let mut rule = RefRule::default();
        let mut scope = MatchScope::None;

        if let Some(defaults) = &self.spec.defaults {
            rule.merge_from(&defaults.rule);
            scope = MatchScope::Defaults;
        }

        if let Some(scheme) = reference.scheme() {
            if let Some(overlay) = self.spec.schemes.get(scheme) {
                rule.merge_from(&overlay.rule);
                scope = MatchScope::Scheme;
            }
        }

        if let Some(binding) = self.spec.types.get(type_name) {
            rule.merge_from(&binding.rule);
            scope = MatchScope::Type;
        }

        if let Some(instance) = instance {
            if let Some(bindings) = self.spec.instances.get(instance) {
                if let Some(binding) = bindings.types.get(type_name) {
                    rule.merge_from(&binding.rule);
                    scope = MatchScope::InstanceType;
                }
            }
        }

        let required = rule.required.unwrap_or(false);
        match reference {
            ReferenceForm::Absent => {
                if required {
                    return Err(SpecError::ReferenceRequired);
                }
            }
            ReferenceForm::Identifier(_) => {
                if !rule.allow_identifier.unwrap_or(false) {
                    return Err(SpecError::IdentifierNotAllowed {
                        type_name: type_name.to_owned(),
                    });
                }
            }
            ReferenceForm::Uri(value) => {
                let scheme = reference.scheme().unwrap_or_default();
                if let Some(allowed) = &rule.schemes {
                    if !allowed.is_empty()
                        && !allowed
                            .iter()
                            .any(|candidate| candidate == "*" || candidate == scheme)
                    {
                        return Err(SpecError::SchemeNotAllowed {
                            scheme: scheme.to_owned(),
                            type_name: type_name.to_owned(),
                        });
                    }
                }
                if let Some(max) = rule.max_length {
                    if value.len() > max {
                        return Err(SpecError::TooLong {
                            actual: value.len(),
                            max,
                        });
                    }
                }
            }
        }

        Ok(BindingMatch {
            type_name: type_name.to_owned(),
            scope,
            rule,
        })
    }
}

/// RefBindings 元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingsMetadata {
    pub domain: String,
    #[serde(default)]
    pub declaration_digest: Option<String>,
}

/// RefBindings 主体。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingsSpec {
    #[serde(default)]
    pub defaults: Option<RefRuleEntry>,
    #[serde(default)]
    pub types: BTreeMap<String, RefRuleEntry>,
    #[serde(default)]
    pub schemes: BTreeMap<String, RefRuleEntry>,
    #[serde(default)]
    pub instances: BTreeMap<String, InstanceBindings>,
}

/// 带 `ref` 包装的一条规则，供 `defaults` / `types` / `schemes` 复用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefRuleEntry {
    #[serde(rename = "ref")]
    pub rule: RefRule,
}

/// 实例级覆盖。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstanceBindings {
    #[serde(default)]
    pub types: BTreeMap<String, RefRuleEntry>,
}

/// 单条引用规则。字段缺省表示“继承上一层”。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefRule {
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub visibility: Option<Visibility>,
    #[serde(default)]
    pub pinning: Option<PinningRequirement>,
    /// 允许的 scheme；`*` 表示任意。缺省表示不限制。
    #[serde(default)]
    pub schemes: Option<Vec<String>>,
    #[serde(default)]
    pub contract: Option<String>,
    #[serde(default)]
    pub max_length: Option<usize>,
    #[serde(default)]
    pub on_unknown_scheme: Option<UnknownSchemePolicy>,
    #[serde(default)]
    pub allow_identifier: Option<bool>,
    /// 保留字段：`none` / `uri` / `identifier`。
    #[serde(default)]
    pub value: Option<String>,
}

impl RefRule {
    fn merge_from(&mut self, overlay: &Self) {
        if overlay.required.is_some() {
            self.required = overlay.required;
        }
        if overlay.visibility.is_some() {
            self.visibility = overlay.visibility;
        }
        if overlay.pinning.is_some() {
            self.pinning = overlay.pinning;
        }
        if overlay.schemes.is_some() {
            self.schemes = overlay.schemes.clone();
        }
        if overlay.contract.is_some() {
            self.contract = overlay.contract.clone();
        }
        if overlay.max_length.is_some() {
            self.max_length = overlay.max_length;
        }
        if overlay.on_unknown_scheme.is_some() {
            self.on_unknown_scheme = overlay.on_unknown_scheme;
        }
        if overlay.allow_identifier.is_some() {
            self.allow_identifier = overlay.allow_identifier;
        }
        if overlay.value.is_some() {
            self.value = overlay.value.clone();
        }
    }
}

/// `thing_ref` 在 Counter/Archive 视图中的可见性档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    ReadGate,
    Domain,
    Hidden,
}

/// 未注册 scheme 的处理策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownSchemePolicy {
    Reject,
    TreatAsIdentifier,
    Allow,
}

/// 规则来源，按从宽到窄排列。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchScope {
    None,
    Defaults,
    Scheme,
    Type,
    InstanceType,
}

/// 匹配结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingMatch {
    pub type_name: String,
    pub scope: MatchScope,
    pub rule: RefRule,
}

impl BindingMatch {
    pub fn requires_reference(&self) -> bool {
        self.rule.required.unwrap_or(false)
    }

    pub fn allowed_schemes(&self) -> Option<&[String]> {
        self.rule.schemes.as_deref()
    }
}

fn validate_rule(rule: &RefRule, context: &str) -> Result<(), SpecError> {
    if let Some(schemes) = &rule.schemes {
        for scheme in schemes {
            if scheme != "*" && !is_valid_scheme(scheme) {
                return Err(SpecError::InvalidBindings(format!(
                    "{context} contains invalid scheme {scheme}"
                )));
            }
        }
    }
    if let Some(max) = rule.max_length {
        if max == 0 || max > 65_536 {
            return Err(SpecError::InvalidBindings(format!(
                "{context} maxLength must be in 1..=65536"
            )));
        }
    }
    if let Some(contract) = &rule.contract {
        if !is_valid_contract_id(contract) {
            return Err(SpecError::InvalidBindings(format!(
                "{context} contract must be id@version: {contract}"
            )));
        }
    }
    if let Some(value) = &rule.value {
        if !matches!(value.as_str(), "none" | "uri" | "identifier") {
            return Err(SpecError::InvalidBindings(format!(
                "{context} value must be none, uri or identifier"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MatchScope, RefBindings};
    use crate::reference::ReferenceForm;
    use crate::SpecError;

    const BINDINGS: &str = r#"{
      "apiVersion": "pact.ref/v1",
      "kind": "RefBindings",
      "metadata": { "domain": "demo" },
      "spec": {
        "defaults": {
          "ref": {
            "required": true,
            "visibility": "read-gate",
            "schemes": ["https", "git"]
          }
        },
        "types": {
          "design": {
            "ref": {
              "schemes": ["git"],
              "contract": "se/design@1"
            }
          }
        },
        "instances": {
          "proj_x": {
            "types": {
              "design": { "ref": { "schemes": ["https"] } }
            }
          }
        }
      }
    }"#;

    fn parse() -> RefBindings {
        serde_json::from_str(BINDINGS).expect("bindings")
    }

    #[test]
    fn validates_and_matches_domain_type() {
        let bindings = parse();
        bindings.validate().expect("valid");
        let reference = ReferenceForm::classify(Some("git://example.com/a")).expect("uri");
        let matched = bindings.resolve(None, "design", &reference).expect("match");
        assert_eq!(matched.scope, MatchScope::Type);
        assert!(matched.requires_reference());
        assert_eq!(matched.rule.contract.as_deref(), Some("se/design@1"));
    }

    #[test]
    fn instance_overrides_domain_type() {
        let bindings = parse();
        let reference = ReferenceForm::classify(Some("https://example.com/a")).expect("uri");
        let matched = bindings
            .resolve(Some("proj_x"), "design", &reference)
            .expect("match");
        assert_eq!(matched.scope, MatchScope::InstanceType);
        assert_eq!(
            matched.allowed_schemes(),
            Some(["https".to_owned()].as_slice())
        );
    }

    #[test]
    fn rejects_scheme_not_allowed() {
        let bindings = parse();
        let reference = ReferenceForm::classify(Some("git://example.com/a")).expect("uri");
        let error = bindings
            .resolve(Some("proj_x"), "design", &reference)
            .expect_err("reject");
        assert!(matches!(error, SpecError::SchemeNotAllowed { .. }));
    }

    #[test]
    fn requires_reference_when_absent() {
        let bindings = parse();
        let error = bindings
            .resolve(None, "design", &ReferenceForm::Absent)
            .expect_err("reject");
        assert_eq!(error, SpecError::ReferenceRequired);
    }

    #[test]
    fn rejects_identifier_by_default() {
        let bindings = parse();
        let reference = ReferenceForm::classify(Some("REQ-001")).expect("identifier");
        let error = bindings
            .resolve(None, "design", &reference)
            .expect_err("reject");
        assert!(matches!(error, SpecError::IdentifierNotAllowed { .. }));
    }

    #[test]
    fn rejects_invalid_domain() {
        let mut bindings = parse();
        bindings.metadata.domain = "bad domain".to_owned();
        assert!(matches!(
            bindings.validate(),
            Err(SpecError::InvalidDomain(_))
        ));
    }
}
