#![allow(dead_code, unused_variables, unused_imports)]
use std::str::FromStr;

// ---- clap
#[derive(clap::Parser, Debug)]
#[command(name = "katnya", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(clap::Subcommand, Debug)]
enum Cmd {
    Check {
        #[arg(long)]
        changed: bool,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}
#[derive(clap::ValueEnum, Clone, Debug)]
enum Format { Text, Json, Sarif, Github }

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Fact { fact: String, ttl_days: u32 }

fn yaml_toml_json() -> anyhow::Result<()> {
    let f: Fact = serde_saphyr::from_str("fact: x\nttl_days: 3\n")?;
    let s: String = serde_saphyr::to_string(&f)?;
    let opts = serde_saphyr::Options::default();
    let f2: Fact = serde_saphyr::from_str_with_options("fact: x\nttl_days: 3\n", opts)?;
    let t: toml::Table = toml::from_str("a = 1")?;
    let ts: String = toml::to_string(&f)?;
    let mut doc: toml_edit::DocumentMut = "a = 1".parse()?;
    doc["b"] = toml_edit::value("x");
    let v: serde_json::Value = serde_json::to_value(&f)?;
    let schema = serde_json::json!({"type":"object"});
    let validator: jsonschema::Validator = jsonschema::validator_for(&schema)?;
    let ok: bool = validator.is_valid(&v);
    for e in validator.iter_errors(&v) { let _ = (e.instance_path().to_string(), e.to_string()); }
    let _ = jsonschema::draft202012::new(&schema)?;
    Ok(())
}

fn sarif() -> anyhow::Result<String> {
    use serde_sarif::sarif::{Sarif, Run, Tool, ToolComponent, Result as SResult, Message};
    let driver = ToolComponent::builder().name("katnya").version("0.1.0").build();
    let tool = Tool::builder().driver(driver).build();
    let res = SResult::builder()
        .rule_id("KAT-VER-001")
        .message(Message::builder().text("x").build())
        .build();
    let run = Run::builder().tool(tool).results(vec![res]).build();
    let sarif = Sarif::builder().version(serde_json::json!("2.1.0")).runs(vec![run]).build();
    Ok(serde_json::to_string(&sarif)?)
}

fn git() -> anyhow::Result<()> {
    let repo: gix::Repository = gix::discover(".")?;
    let head = repo.rev_parse_single("HEAD")?;
    let base = repo.rev_parse_single("origin/main")?;
    let mb: gix::Id<'_> = repo.merge_base(head.detach(), base.detach())?;
    let mb_tree = mb.object()?.into_commit().tree()?;
    let head_commit = head.object()?.into_commit();
    let head_tree = head_commit.tree()?;
    let changes = repo.diff_tree_to_tree(Some(&mb_tree), Some(&head_tree), None)?;
    for c in &changes { let _loc = c.location(); }
    if let Some(entry) = head_tree.lookup_entry_by_path("Cargo.lock")? {
        let blob = entry.object()?;
        let bytes: &[u8] = &blob.data;
    }
    let msg = head_commit.message()?;
    if let Some(body) = msg.body() {
        for t in body.trailers() { let _ = (t.token, t.value); }
    }
    Ok(())
}

fn astgrep2() {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;
    let lang = SupportLang::Rust;
    let grep = lang.ast_grep("fn f() { unsafe { x() } }");
    let root = grep.root();
    for m in root.find_all("unsafe { $$$ }") {
        let _ = (m.text(), m.start_pos().line(), m.range());
    }
}

fn rust_src() -> anyhow::Result<()> {
    let file: syn::File = syn::parse_file("fn f() {}")?;
    struct V; impl<'ast> syn::visit::Visit<'ast> for V { fn visit_expr_unsafe(&mut self, i: &'ast syn::ExprUnsafe) { let _ = i.unsafe_token.span.start(); } }
    syn::visit::Visit::visit_file(&mut V, &file);
    let md = cargo_metadata::MetadataCommand::new().no_deps().exec()?;
    for p in md.workspace_packages() { let _ = (&p.name, &p.version, &p.manifest_path); }
    let lock = cargo_lock::Lockfile::load("Cargo.lock")?;
    let lock2 = cargo_lock::Lockfile::from_str("version = 4")?;
    for p in &lock.packages { let _ = (p.name.as_str(), &p.version, &p.source, &p.checksum); }
    let v = semver::Version::parse("1.2.3")?;
    let r = semver::VersionReq::parse(">=1.2")?;
    let _ = r.matches(&v);
    let purl = packageurl::PackageUrl::from_str("pkg:cargo/serde@1.0.0")?;
    let _ = (purl.ty(), purl.name(), purl.version());
    Ok(())
}

async fn http() -> anyhow::Result<()> {
    let c = reqwest::Client::builder().user_agent("katnya").https_only(true).build()?;
    let v: serde_json::Value = c.get("https://api.osv.dev/v1/query").send().await?.error_for_status()?.json().await?;
    let gh = octocrab::Octocrab::builder().personal_token("x".to_string()).build()?;
    let prs = gh.pulls("o", "r").list().send().await?;
    let raw: serde_json::Value = gh.get("/repos/o/r/security-advisories", None::<&()>).await?;
    let app = octocrab::Octocrab::builder()
        .app(octocrab::models::AppId(1), jsonwebtoken::EncodingKey::from_rsa_pem(b"")?)
        .build()?;
    Ok(())
}

fn sig() -> anyhow::Result<()> {
    use sigstore_verify::{verify, VerificationPolicy};
    use sigstore_verify::trust_root::{TrustedRoot, SIGSTORE_GITHUB_TRUSTED_ROOT, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
    use sigstore_verify::types::Bundle;
    let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)?;
    let bundle = Bundle::from_json("{}")?;
    let artifact = std::fs::read("katnya")?;
    let policy = VerificationPolicy::default()
        .require_identity("https://github.com/o/katnya/.github/workflows/release.yml@refs/tags/v0.1.0")
        .require_issuer("https://token.actions.githubusercontent.com");
    let res: sigstore_verify::VerificationResult = verify(&artifact, &bundle, &policy, &root)?;
    Ok(())
}

fn hashing() {
    use sha2::Digest;
    let d = sha2::Sha256::digest(b"x");
    let h = hex::encode(d);
    let b = blake3::hash(b"x").to_hex();
    let mut hasher = blake3::Hasher::new(); hasher.update(b"x"); let _ = hasher.finalize();
}

fn keystore() -> anyhow::Result<()> {
    let e = keyring::Entry::new("katnya-gateway", "local-token")?;
    e.set_password("t")?;
    let p: String = e.get_password()?;
    Ok(())
}

fn fs_walk() -> anyhow::Result<()> {
    let p: &camino::Utf8Path = camino::Utf8Path::new("a/b");
    let pb = camino::Utf8PathBuf::from_path_buf(std::path::PathBuf::from("x")).unwrap();
    let tmp = tempfile::tempdir()?;
    let nf = tempfile::NamedTempFile::new_in(tmp.path())?;
    let (_f, _path) = nf.keep()?;
    for ent in ignore::WalkBuilder::new(".").hidden(false).git_ignore(true).build() { let _ = ent?.path().to_owned(); }
    let gs = globset::GlobSetBuilder::new().add(globset::Glob::new(".katnya/**")?).build()?;
    let _ = gs.is_match("a");
    let re = regex::Regex::new(r"^(feat|fix)\((\w+)\): .{1,72}$")?;
    let diff = similar::TextDiff::from_lines("a\n", "b\n");
    let u = diff.unified_diff().context_radius(3).header("a", "b").to_string();
    let now = jiff::Timestamp::now();
    let ttl = now.checked_add(jiff::SignedDuration::from_hours(72))?;
    let z = now.to_zoned(jiff::tz::TimeZone::UTC);
    Ok(())
}

fn telemetry() -> anyhow::Result<()> {
    use tracing_subscriber::prelude::*; use opentelemetry_otlp::WithExportConfig;
    let exporter = opentelemetry_otlp::LogExporter::builder().with_http().with_endpoint("http://localhost:4318/v1/logs").build()?;
    let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder().with_batch_exporter(exporter).build();
    let otel_layer = opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&provider);
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .init();
    tracing::info!(tool = "x", "mcp tool call");
    provider.shutdown()?;
    Ok(())
}

#[derive(thiserror::Error, Debug)]
enum KatErr { #[error("fact {0} expired")] Expired(String) }

mod mcp {
    use rmcp::{ServerHandler, ServiceExt, model::*, tool, tool_router, tool_handler, handler::server::{router::tool::ToolRouter, wrapper::Parameters}};
    #[derive(Clone)]
    pub struct Docs { tool_router: ToolRouter<Self> }
    #[derive(serde::Deserialize, rmcp::schemars::JsonSchema)]
    pub struct DocsArgs { pub package: String }
    #[tool_router]
    impl Docs {
        pub fn new() -> Self { Self { tool_router: Self::tool_router() } }
        #[tool(description = "Docs for the pinned version")]
        async fn docs(&self, Parameters(a): Parameters<DocsArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
            Ok(CallToolResult::success(vec![ContentBlock::text(a.package)]))
        }
    }
    #[tool_handler]
    impl ServerHandler for Docs {}

    pub async fn serve_stdio() -> anyhow::Result<()> {
        let svc = Docs::new().serve(rmcp::transport::stdio()).await?;
        svc.waiting().await?;
        Ok(())
    }
    pub async fn upstream() -> anyhow::Result<()> {
        let mut cmd = tokio::process::Command::new("server");
        let transport = rmcp::transport::TokioChildProcess::new(cmd)?;
        let client = ().serve(transport).await?;
        let tools = client.list_all_tools().await?;
        for t in &tools { let _ = (&t.name, &t.description, &t.input_schema); }
        let r = client.call_tool(CallToolRequestParams::new("docs")).await?;
        client.cancel().await?;
        Ok(())
    }
    pub async fn http() -> anyhow::Result<()> {
        use rmcp::transport::streamable_http_server::{StreamableHttpService, StreamableHttpServerConfig, session::local::LocalSessionManager};
        let cfg = StreamableHttpServerConfig::default().with_allowed_hosts(["127.0.0.1"]);
        let svc = StreamableHttpService::new(|| Ok(Docs::new()), LocalSessionManager::default().into(), cfg);
        let app = axum::Router::new().nest_service("/mcp", svc);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test] fn yaml_toml_json_runs() { super::yaml_toml_json().unwrap(); }
    #[test] fn sarif_snapshot() {
        let s: serde_json::Value = serde_json::from_str(&super::sarif().unwrap()).unwrap();
        insta::assert_json_snapshot!(s["runs"][0]["results"][0]["ruleId"], @r#""KAT-VER-001""#);
    }
    #[test] fn astgrep_runs() { super::astgrep2(); }
    #[test] fn hashing_runs() { super::hashing(); }
    #[test] fn rust_src_runs() { super::rust_src().unwrap(); }
    #[test] fn fs_walk_runs() { super::fs_walk().unwrap(); }
    #[test] fn sigstore_root_parses() {
        use sigstore_verify::trust_root::{TrustedRoot, SIGSTORE_PRODUCTION_TRUSTED_ROOT};
        TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap();
    }
    #[test] fn tls_client_builds() {
        reqwest::Client::builder().user_agent("katnya").https_only(true).build().unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            octocrab::Octocrab::builder().personal_token("x".to_string()).build().unwrap();
        });
    }
    proptest::proptest! {
        #[test] fn yaml_roundtrip(n in 0u32..10000, s in "[a-z]{1,12}") {
            let f = super::Fact { fact: s.clone(), ttl_days: n };
            let y = serde_saphyr::to_string(&f).unwrap();
            let g: super::Fact = serde_saphyr::from_str(&y).unwrap();
            proptest::prop_assert_eq!(g.fact, s); proptest::prop_assert_eq!(g.ttl_days, n);
        }
    }
}
