//! PACT 物引一致性测试 runner。
//!
//! 读取 `conformance/cases/**/*.yaml`，把每个入口用例交给
//! `pact-ref-spec::validate_entry` 执行，逐条输出结果并以退出码表示是否全部通过。
//!
//! 首版只覆盖入口票面校验（URI profile / Identifier / `∅` / RefBindings 策略）；
//! resolve/invoke 用例待 adapter 假服务方案确定后再扩展。

use std::fs;
use std::path::{Path, PathBuf};

use pact_ref_spec::{validate_entry, EntryError, EntryRef, RefBindings, SpecError};
use serde::Deserialize;

/// 用例文件格式版本。
const CASE_API_VERSION: &str = "conformance.pact-ref/v1";
/// 用例类型。
const CASE_KIND: &str = "EntryCase";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaseFile {
    api_version: String,
    kind: String,
    name: String,
    spec: CaseSpec,
    expect: Expectation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaseSpec {
    #[serde(rename = "type")]
    type_name: String,
    #[serde(default)]
    instance: Option<String>,
    reference: ReferenceInput,
    #[serde(default)]
    bindings: Option<RefBindings>,
}

/// 入口票面三态：字段缺失 / 显式 `null` / 字符串。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, tag = "state")]
enum ReferenceInput {
    Missing,
    Null,
    Value { value: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Ok,
    Error,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expectation {
    outcome: Outcome,
    /// `outcome: ok` 时期望的规范化票面；缺省表示期望 `∅`。
    #[serde(default)]
    reference: Option<String>,
    /// `outcome: error` 时的 HTTP 错误码（与 `pact-http` 对齐）。
    #[serde(default)]
    error: Option<String>,
    /// 可选：更细的 `SpecError` 变体名，用于区分同为 `InvalidThingRef` 的原因。
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Default)]
struct Report {
    total: usize,
    failures: Vec<String>,
}

fn main() {
    let mut cases_dir = PathBuf::from("conformance/cases");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--cases" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("error: --cases requires a directory");
                    std::process::exit(2);
                };
                cases_dir = PathBuf::from(value);
            }
            "--help" | "-h" => {
                println!(
                    "usage: {} [--cases <dir>]\n\n默认读取 conformance/cases。",
                    env!("CARGO_PKG_NAME")
                );
                return;
            }
            other => {
                eprintln!("error: unknown argument {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    match run_cases(&cases_dir) {
        Ok(report) => {
            let failed = report.failures.len();
            println!();
            println!("{} passed, {failed} failed", report.total - failed);
            if failed == 0 {
                return;
            }
            for failure in &report.failures {
                eprintln!("FAILED {failure}");
            }
            std::process::exit(1);
        }
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(2);
        }
    }
}

fn run_cases(cases_dir: &Path) -> Result<Report, String> {
    let mut files = Vec::new();
    collect_case_files(cases_dir, &mut files)?;
    if files.is_empty() {
        return Err(format!("no case files under {}", cases_dir.display()));
    }
    files.sort();

    let mut report = Report::default();
    for file in files {
        let text =
            fs::read_to_string(&file).map_err(|error| format!("{}: {error}", file.display()))?;
        let case: CaseFile =
            serde_yaml::from_str(&text).map_err(|error| format!("{}: {error}", file.display()))?;
        report.total += 1;
        match execute_case(&case) {
            Ok(()) => println!("ok   {}", case.name),
            Err(message) => {
                println!("FAIL {} ({message})", case.name);
                report
                    .failures
                    .push(format!("{}: {} ({message})", file.display(), case.name));
            }
        }
    }
    Ok(report)
}

fn collect_case_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        paths.push(entry.path());
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_case_files(&path, out)?;
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yaml" | "yml")
        ) {
            out.push(path);
        }
    }
    Ok(())
}

fn execute_case(case: &CaseFile) -> Result<(), String> {
    if case.api_version != CASE_API_VERSION {
        return Err(format!(
            "apiVersion must be {CASE_API_VERSION}, got {}",
            case.api_version
        ));
    }
    if case.kind != CASE_KIND {
        return Err(format!("kind must be {CASE_KIND}, got {}", case.kind));
    }
    if let Some(bindings) = &case.spec.bindings {
        bindings
            .validate()
            .map_err(|error| format!("invalid bindings: {error}"))?;
    }

    let input = match &case.spec.reference {
        ReferenceInput::Missing => EntryRef::Missing,
        ReferenceInput::Null => EntryRef::Absent,
        ReferenceInput::Value { value } => EntryRef::Present(value),
    };
    let result = validate_entry(
        case.spec.bindings.as_ref(),
        case.spec.instance.as_deref(),
        &case.spec.type_name,
        input,
    );

    match case.expect.outcome {
        Outcome::Ok => {
            if case.expect.error.is_some() || case.expect.reason.is_some() {
                return Err("outcome=ok must not declare error or reason".to_owned());
            }
            match result {
                Ok(actual) => {
                    if actual.as_deref() != case.expect.reference.as_deref() {
                        return Err(format!(
                            "expected {:?}, got {:?}",
                            case.expect.reference, actual
                        ));
                    }
                    Ok(())
                }
                Err(error) => Err(format!(
                    "expected success, got {} ({})",
                    error_code(&error),
                    error
                )),
            }
        }
        Outcome::Error => {
            if case.expect.reference.is_some() {
                return Err("outcome=error must not declare reference".to_owned());
            }
            let Some(expected) = case.expect.error.as_deref() else {
                return Err("outcome=error requires expect.error".to_owned());
            };
            match result {
                Ok(actual) => Err(format!("expected {expected}, got success ({actual:?})")),
                Err(error) => {
                    let code = error_code(&error);
                    if code != expected {
                        return Err(format!("expected {expected}, got {code} ({error})"));
                    }
                    if let Some(reason) = case.expect.reason.as_deref() {
                        let actual_reason = error_reason(&error);
                        if actual_reason != reason {
                            return Err(format!(
                                "expected reason {reason}, got {actual_reason} ({error})"
                            ));
                        }
                    }
                    Ok(())
                }
            }
        }
    }
}

/// 与 `pact-http` 的入口错误码保持一致（`crates/pact-http/src/server.rs`）。
fn error_code(error: &EntryError) -> &'static str {
    match error {
        EntryError::Missing => "ThingRefMissing",
        EntryError::Invalid(SpecError::ReferenceRequired) => "ThingRefRequired",
        EntryError::Invalid(SpecError::PinningRequired { .. }) => "ThingRefUnpinned",
        EntryError::Invalid(_) => "InvalidThingRef",
    }
}

fn error_reason(error: &EntryError) -> &'static str {
    match error {
        EntryError::Missing => "Missing",
        EntryError::Invalid(error) => spec_error_name(error),
    }
}

fn spec_error_name(error: &SpecError) -> &'static str {
    match error {
        SpecError::EmptyReference => "EmptyReference",
        SpecError::BarePath(_) => "BarePath",
        SpecError::ControlCharacter(_) => "ControlCharacter",
        SpecError::TooLong { .. } => "TooLong",
        SpecError::MalformedUri(_) => "MalformedUri",
        SpecError::InvalidScheme(_) => "InvalidScheme",
        SpecError::UserInfoNotAllowed => "UserInfoNotAllowed",
        SpecError::InvalidIdentifier(_) => "InvalidIdentifier",
        SpecError::InvalidDomain(_) => "InvalidDomain",
        SpecError::InvalidDigest(_) => "InvalidDigest",
        SpecError::InvalidBindings(_) => "InvalidBindings",
        SpecError::InvalidContract(_) => "InvalidContract",
        SpecError::InvalidTombstone(_) => "InvalidTombstone",
        SpecError::ReferenceRequired => "ReferenceRequired",
        SpecError::SchemeNotAllowed { .. } => "SchemeNotAllowed",
        SpecError::IdentifierNotAllowed { .. } => "IdentifierNotAllowed",
        SpecError::ValueFormMismatch { .. } => "ValueFormMismatch",
        SpecError::PinningRequired { .. } => "PinningRequired",
    }
}

#[cfg(test)]
mod tests {
    use super::{execute_case, run_cases, CaseFile};
    use std::path::Path;

    fn load(yaml: &str) -> CaseFile {
        serde_yaml::from_str(yaml).expect("case file")
    }

    #[test]
    fn entry_cases_pass() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cases");
        let report = run_cases(&dir).expect("run conformance cases");
        assert!(report.total > 0, "no cases executed");
        assert!(report.failures.is_empty(), "{:#?}", report.failures);
    }

    #[test]
    fn detects_mismatched_expectation() {
        let case = load(
            r#"
apiVersion: conformance.pact-ref/v1
kind: EntryCase
name: self-check/mismatch
spec:
  type: design
  reference:
    state: value
    value: https://example.com/a
expect:
  outcome: ok
  reference: https://example.com/b
"#,
        );
        assert!(execute_case(&case).is_err());
    }

    #[test]
    fn detects_unexpected_success() {
        let case = load(
            r#"
apiVersion: conformance.pact-ref/v1
kind: EntryCase
name: self-check/unexpected-success
spec:
  type: design
  reference:
    state: value
    value: https://example.com/a
expect:
  outcome: error
  error: InvalidThingRef
"#,
        );
        assert!(execute_case(&case).is_err());
    }
}
