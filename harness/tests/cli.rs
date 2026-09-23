use assert_cmd::Command;
use predicates::prelude::*;
#[test]
fn help_lists_check() {
    Command::cargo_bin("stack-harness").unwrap().arg("--help").assert()
        .success().stdout(predicate::str::contains("check"));
}
#[test]
fn bad_format_fails() {
    Command::cargo_bin("stack-harness").unwrap().args(["check", "--format", "xml"]).assert()
        .failure().stderr(predicate::str::contains("invalid value"));
}
