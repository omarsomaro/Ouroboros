use base64::{engine::general_purpose, Engine as _};
use futures::{stream, StreamExt};
use handshacke::api::{create_api_server, Streams};
use handshacke::state::AppState;
use reqwest::header;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

fn build_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

async fn spawn_api_server_with_token(
    api_token: Option<&str>,
) -> anyhow::Result<(String, AppState, JoinHandle<()>)> {
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr: SocketAddr = probe.local_addr()?;
    drop(probe);

    let app_state = AppState::default();
    let (streams, _rx_out) = Streams::new();
    let bind = addr.to_string();
    let app_clone = app_state.clone();

    let token = api_token.map(|v| v.to_string());
    let server = tokio::spawn(async move {
        let _ = create_api_server(app_clone, streams, bind, token).await;
    });

    let base_url = format!("http://{}", addr);
    let client = reqwest::Client::new();

    for _ in 0..80 {
        let mut req = client.get(format!("{}/v1/status", base_url));
        if let Some(token) = api_token {
            req = req.bearer_auth(token);
        }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                return Ok((base_url, app_state, server));
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    server.abort();
    Err(anyhow::anyhow!("api server did not become ready"))
}

async fn spawn_api_server() -> anyhow::Result<(String, AppState, JoinHandle<()>)> {
    spawn_api_server_with_token(None).await
}

fn cors_origin_for_test() -> String {
    let defaults = "http://localhost:5173,http://127.0.0.1:5173,tauri://localhost";
    let raw = std::env::var("HANDSHACKE_API_CORS_ORIGINS").unwrap_or_else(|_| defaults.to_string());
    raw.split(',')
        .map(|v| v.trim())
        .find(|v| !v.is_empty())
        .unwrap_or("http://localhost:5173")
        .to_string()
}

#[tokio::test]
async fn api_ethersync_files_publish_emits_sse_events() -> anyhow::Result<()> {
    let (base_url, app_state, server) = spawn_api_server().await?;
    let client = reqwest::Client::new();

    let run = async {
        let start_resp = client
            .post(format!("{}/v1/ethersync/start", base_url))
            .json(&json!({
                "bind_addr": "127.0.0.1:0"
            }))
            .send()
            .await?;
        assert!(
            start_resp.status().is_success(),
            "start failed: {}",
            start_resp.status()
        );

        let mut events_resp = client
            .get(format!("{}/v1/ethersync/events", base_url))
            .send()
            .await?;
        assert_eq!(events_resp.status(), reqwest::StatusCode::OK);
        let content_type = events_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(content_type.contains("text/event-stream"));

        let payload = build_payload(1500);
        let publish_resp = client
            .post(format!("{}/v1/ethersync/files/publish", base_url))
            .json(&json!({
                "passphrase": "amber valley orbit",
                "filename": "sample.bin",
                "file_b64": general_purpose::STANDARD.encode(&payload),
                "chunk_size": 512
            }))
            .send()
            .await?;
        assert_eq!(publish_resp.status(), reqwest::StatusCode::OK);
        let publish_json: Value = publish_resp.json().await?;
        assert_eq!(publish_json["filename"], "sample.bin");
        assert_eq!(publish_json["total_bytes"], 1500);
        assert_eq!(publish_json["total_chunks"], 3);
        assert_eq!(publish_json["published_chunks"], 3);

        timeout(Duration::from_secs(6), async {
            loop {
                let maybe_chunk = events_resp.chunk().await?;
                let Some(chunk) = maybe_chunk else {
                    return Err(anyhow::anyhow!("events stream closed before file events"));
                };
                let text = String::from_utf8_lossy(&chunk);
                if text.contains("space_file_publish_started")
                    || text.contains("space_file_chunk_published")
                    || text.contains("space_file_publish_completed")
                {
                    return Ok::<(), anyhow::Error>(());
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting SSE file events"))??;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = app_state.ethersync_stop().await;
    server.abort();
    let _ = server.await;
    run
}

#[tokio::test]
async fn api_ethersync_files_publish_rejects_invalid_base64() -> anyhow::Result<()> {
    let (base_url, app_state, server) = spawn_api_server().await?;
    let client = reqwest::Client::new();

    let run = async {
        let start_resp = client
            .post(format!("{}/v1/ethersync/start", base_url))
            .json(&json!({
                "bind_addr": "127.0.0.1:0"
            }))
            .send()
            .await?;
        assert!(
            start_resp.status().is_success(),
            "start failed: {}",
            start_resp.status()
        );

        let resp = client
            .post(format!("{}/v1/ethersync/files/publish", base_url))
            .json(&json!({
                "passphrase": "amber valley orbit",
                "filename": "bad.bin",
                "file_b64": "%%%%not-base64%%%%"
            }))
            .send()
            .await?;

        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
        let body_text = resp.text().await?;
        assert!(body_text.contains("invalid file_b64"));

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = app_state.ethersync_stop().await;
    server.abort();
    let _ = server.await;
    run
}

#[tokio::test]
async fn api_ethersync_requires_bearer_when_token_enabled() -> anyhow::Result<()> {
    let token = "super-secret-token";
    let (base_url, app_state, server) = spawn_api_server_with_token(Some(token)).await?;
    let client = reqwest::Client::new();

    let run = async {
        let unauthorized = client
            .get(format!("{}/v1/ethersync/status", base_url))
            .send()
            .await?;
        assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

        let wrong = client
            .get(format!("{}/v1/ethersync/status", base_url))
            .bearer_auth("wrong-token")
            .send()
            .await?;
        assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);

        let authorized = client
            .get(format!("{}/v1/ethersync/status", base_url))
            .bearer_auth(token)
            .send()
            .await?;
        assert_eq!(authorized.status(), reqwest::StatusCode::OK);

        let start_resp = client
            .post(format!("{}/v1/ethersync/start", base_url))
            .bearer_auth(token)
            .json(&json!({
                "bind_addr": "127.0.0.1:0"
            }))
            .send()
            .await?;
        assert!(
            start_resp.status().is_success(),
            "start failed: {}",
            start_resp.status()
        );

        let payload = build_payload(64);
        let publish_unauthorized = client
            .post(format!("{}/v1/ethersync/files/publish", base_url))
            .json(&json!({
                "passphrase": "amber valley orbit",
                "filename": "sample.bin",
                "file_b64": general_purpose::STANDARD.encode(&payload),
                "chunk_size": 32
            }))
            .send()
            .await?;
        assert_eq!(
            publish_unauthorized.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );

        let publish_authorized = client
            .post(format!("{}/v1/ethersync/files/publish", base_url))
            .bearer_auth(token)
            .json(&json!({
                "passphrase": "amber valley orbit",
                "filename": "sample.bin",
                "file_b64": general_purpose::STANDARD.encode(&payload),
                "chunk_size": 32
            }))
            .send()
            .await?;
        assert_eq!(publish_authorized.status(), reqwest::StatusCode::OK);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = app_state.ethersync_stop().await;
    server.abort();
    let _ = server.await;
    run
}

#[tokio::test]
async fn api_ethersync_preflight_options_bypasses_auth_and_sets_cors_headers() -> anyhow::Result<()>
{
    let token = "super-secret-token";
    let (base_url, app_state, server) = spawn_api_server_with_token(Some(token)).await?;
    let client = reqwest::Client::new();
    let origin = cors_origin_for_test();

    let run = async {
        let preflight = client
            .request(
                reqwest::Method::OPTIONS,
                format!("{}/v1/ethersync/files/publish", base_url),
            )
            .header(header::ORIGIN, &origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization,content-type",
            )
            .send()
            .await?;

        assert!(
            preflight.status().is_success(),
            "preflight status={}",
            preflight.status()
        );
        assert_ne!(
            preflight.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "preflight must not be blocked by bearer auth"
        );

        let allow_origin = preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(allow_origin, origin);

        let allow_methods = preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        assert!(allow_methods.contains("post"));
        assert!(allow_methods.contains("options"));

        let allow_headers = preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        assert!(allow_headers.contains("authorization"));
        assert!(allow_headers.contains("content-type"));

        let unauthorized = client
            .get(format!("{}/v1/ethersync/status", base_url))
            .send()
            .await?;
        assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = app_state.ethersync_stop().await;
    server.abort();
    let _ = server.await;
    run
}

#[tokio::test]
async fn api_ethersync_rate_limit_triggers_on_publish_file_burst() -> anyhow::Result<()> {
    let (base_url, app_state, server) = spawn_api_server().await?;
    let client = reqwest::Client::new();

    let run = async {
        let url = format!("{}/v1/ethersync/files/publish", base_url);
        let results = stream::iter(0..600usize)
            .map(|_| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    client
                        .post(url)
                        .json(&json!({
                            "passphrase": "rate-limit-space",
                            "filename": "sample.bin",
                            "file_b64": "%%%%invalid%%%%"
                        }))
                        .send()
                        .await
                        .map(|resp| resp.status())
                }
            })
            .buffer_unordered(64)
            .collect::<Vec<_>>()
            .await;

        let mut too_many = 0usize;
        let mut bad_request = 0usize;
        for item in results {
            let status = item?;
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                too_many += 1;
            } else if status == reqwest::StatusCode::BAD_REQUEST {
                bad_request += 1;
            } else {
                return Err(anyhow::anyhow!("unexpected status {}", status));
            }
        }

        assert!(
            too_many > 0,
            "expected at least one 429, got too_many={} bad_request={}",
            too_many,
            bad_request
        );
        assert!(
            bad_request > 0,
            "expected at least one 400 before limiter saturates"
        );

        Ok::<(), anyhow::Error>(())
    }
    .await;

    let _ = app_state.ethersync_stop().await;
    server.abort();
    let _ = server.await;
    run
}
