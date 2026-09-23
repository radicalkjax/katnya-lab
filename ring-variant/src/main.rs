#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider().install_default().expect("provider");
    let c = reqwest::Client::builder().user_agent("katnya-lab").https_only(true).build()?;
    let v: serde_json::Value = c.get("https://api.github.com/zen").send().await?.error_for_status()?.json().await.unwrap_or(serde_json::Value::Null);
    let _ = v;
    let st = c.get("https://api.github.com/").send().await?.status();
    let gh = octocrab::Octocrab::builder().build()?;
    let meta: serde_json::Value = gh.get("/meta", None::<&()>).await?;
    let k = jsonwebtoken::EncodingKey::from_secret(b"k");
    let t = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &serde_json::json!({"sub":"x","exp":4102444800u64}), &k)?;
    println!("ring-variant OK: reqwest status={st} octocrab /meta keys={} jwt_len={}", meta.as_object().map(|o| o.len()).unwrap_or(0), t.len());
    Ok(())
}
