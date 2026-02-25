use handshacke::crypto::{open, seal_with_nonce, ClearPayload, NonceSeq, NONCE_DOMAIN_APP};
use handshacke::derive::derive_from_passphrase_v2;
use handshacke::session_noise::{classic_noise_params, run_noise_upgrade_io, NoiseRole};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};

const DERIVE_RUNS: usize = 8;
const NOISE_RUNS: usize = 8;
const THROUGHPUT_ITERATIONS: usize = 10_000;
const THROUGHPUT_PAYLOAD_BYTES: usize = 1024;

const BUDGET_DERIVE_AVG_MS_MAX: f64 = 300.0;
const BUDGET_NOISE_AVG_MS_MAX: f64 = 120.0;
const BUDGET_THROUGHPUT_MIBS_MIN: f64 = 10.0;
const BUDGET_MEMORY_DELTA_KIB_MAX: u64 = 131_072;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, BoxError>;

#[derive(Debug, Serialize)]
struct PerfReport {
    generated_at_unix_ms: u64,
    derive_avg_ms: f64,
    noise_handshake_avg_ms: f64,
    crypto_throughput_mib_s: f64,
    memory_hwm_delta_kib: Option<u64>,
    budgets: BudgetEvaluation,
}

#[derive(Debug, Serialize)]
struct BudgetEvaluation {
    derive_avg_ms_max: f64,
    noise_avg_ms_max: f64,
    throughput_mib_s_min: f64,
    memory_delta_kib_max: u64,
    derive_ok: bool,
    noise_ok: bool,
    throughput_ok: bool,
    memory_ok: bool,
    all_ok: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let (check_budgets, output_path) = parse_args()?;

    let memory_before = memory_hwm_kib();
    let derive_avg_ms = bench_derive()?;
    let noise_handshake_avg_ms = bench_noise_handshake().await?;
    let crypto_throughput_mib_s = bench_crypto_throughput()?;
    let memory_after = memory_hwm_kib();

    let memory_hwm_delta_kib = match (memory_before, memory_after) {
        (Some(before), Some(after)) => Some(after.saturating_sub(before)),
        _ => None,
    };

    let budgets = evaluate_budgets(
        derive_avg_ms,
        noise_handshake_avg_ms,
        crypto_throughput_mib_s,
        memory_hwm_delta_kib,
    );

    let report = PerfReport {
        generated_at_unix_ms: now_unix_ms(),
        derive_avg_ms,
        noise_handshake_avg_ms,
        crypto_throughput_mib_s,
        memory_hwm_delta_kib,
        budgets,
    };

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = output_path {
        fs::write(path, &json)?;
    } else {
        println!("{json}");
    }

    if check_budgets && !report.budgets.all_ok {
        return Err(std::io::Error::other("performance budgets exceeded").into());
    }

    Ok(())
}

fn parse_args() -> Result<(bool, Option<PathBuf>)> {
    let mut check_budgets = false;
    let mut output_path: Option<PathBuf> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--check-budgets" => {
                check_budgets = true;
                i += 1;
            }
            "--output" => {
                let next = args.get(i + 1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--output requires a path",
                    )
                })?;
                output_path = Some(PathBuf::from(next));
                i += 2;
            }
            unknown => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown argument: {unknown}"),
                )
                .into());
            }
        }
    }

    Ok((check_budgets, output_path))
}

fn bench_derive() -> Result<f64> {
    let passphrase = "state-of-the-art benchmark passphrase";
    let mut total_ms = 0.0f64;

    for _ in 0..DERIVE_RUNS {
        let start = Instant::now();
        let _params = derive_from_passphrase_v2(passphrase)?;
        total_ms += start.elapsed().as_secs_f64() * 1000.0;
    }

    Ok(total_ms / DERIVE_RUNS as f64)
}

async fn bench_noise_handshake() -> Result<f64> {
    let mut total_ms = 0.0f64;

    for _ in 0..NOISE_RUNS {
        total_ms += run_noise_handshake_once().await?;
    }

    Ok(total_ms / NOISE_RUNS as f64)
}

async fn run_noise_handshake_once() -> Result<f64> {
    let (i_to_r_tx, i_to_r_rx) = mpsc::channel::<Vec<u8>>(16);
    let (r_to_i_tx, r_to_i_rx) = mpsc::channel::<Vec<u8>>(16);

    let i_recv = std::sync::Arc::new(Mutex::new(r_to_i_rx));
    let r_recv = std::sync::Arc::new(Mutex::new(i_to_r_rx));

    let base_key = [7u8; 32];
    let tag16 = 0x1337u16;
    let tag8 = 0x42u8;
    let noise_params = classic_noise_params()?;

    let start = Instant::now();

    let initiator = {
        let tx = i_to_r_tx.clone();
        let rx = std::sync::Arc::clone(&i_recv);
        let params = noise_params.clone();
        tokio::spawn(async move {
            run_noise_upgrade_io(
                NoiseRole::Initiator,
                move |data: Vec<u8>| {
                    let tx = tx.clone();
                    async move {
                        tx.send(data)
                            .await
                            .map_err(|e| format!("initiator send failed: {}", e))
                    }
                },
                move || {
                    let rx = std::sync::Arc::clone(&rx);
                    async move {
                        let mut guard = rx.lock().await;
                        guard
                            .recv()
                            .await
                            .ok_or_else(|| "initiator recv closed".to_string())
                    }
                },
                &base_key,
                tag16,
                tag8,
                params,
                64 * 1024,
            )
            .await
        })
    };

    let responder = {
        let tx = r_to_i_tx.clone();
        let rx = std::sync::Arc::clone(&r_recv);
        let params = noise_params;
        tokio::spawn(async move {
            run_noise_upgrade_io(
                NoiseRole::Responder,
                move |data: Vec<u8>| {
                    let tx = tx.clone();
                    async move {
                        tx.send(data)
                            .await
                            .map_err(|e| format!("responder send failed: {}", e))
                    }
                },
                move || {
                    let rx = std::sync::Arc::clone(&rx);
                    async move {
                        let mut guard = rx.lock().await;
                        guard
                            .recv()
                            .await
                            .ok_or_else(|| "responder recv closed".to_string())
                    }
                },
                &base_key,
                tag16,
                tag8,
                params,
                64 * 1024,
            )
            .await
        })
    };

    let (init_res, resp_res) = tokio::join!(initiator, responder);
    let init_key = init_res.map_err(|e| std::io::Error::other(e.to_string()))??;
    let resp_key = resp_res.map_err(|e| std::io::Error::other(e.to_string()))??;
    if init_key != resp_key {
        return Err(std::io::Error::other("noise handshake produced mismatched keys").into());
    }

    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn bench_crypto_throughput() -> Result<f64> {
    let key = [0x22u8; 32];
    let tag16 = 0x5151u16;
    let tag8 = 0x33u8;
    let mut nonce_seq = NonceSeq::new(&key, NONCE_DOMAIN_APP, 0x01)?;
    let data = vec![0xABu8; THROUGHPUT_PAYLOAD_BYTES];

    let start = Instant::now();
    for _ in 0..THROUGHPUT_ITERATIONS {
        let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
        let clear = ClearPayload {
            ts_ms: 0,
            seq,
            data: data.clone(),
        };
        let pkt = seal_with_nonce(&key, tag16, tag8, &clear, &nonce)?;
        let opened = open(&key, &pkt, tag16, tag8)
            .ok_or_else(|| std::io::Error::other("open() failed in throughput benchmark"))?;
        if opened.data.len() != THROUGHPUT_PAYLOAD_BYTES {
            return Err(
                std::io::Error::other("invalid payload size in throughput benchmark").into(),
            );
        }
    }
    let elapsed = start.elapsed().as_secs_f64();

    let total_bytes = (THROUGHPUT_ITERATIONS * THROUGHPUT_PAYLOAD_BYTES) as f64;
    let mib_per_sec = total_bytes / elapsed / (1024.0 * 1024.0);
    Ok(mib_per_sec)
}

fn evaluate_budgets(
    derive_avg_ms: f64,
    noise_handshake_avg_ms: f64,
    crypto_throughput_mib_s: f64,
    memory_hwm_delta_kib: Option<u64>,
) -> BudgetEvaluation {
    let derive_ok = derive_avg_ms <= BUDGET_DERIVE_AVG_MS_MAX;
    let noise_ok = noise_handshake_avg_ms <= BUDGET_NOISE_AVG_MS_MAX;
    let throughput_ok = crypto_throughput_mib_s >= BUDGET_THROUGHPUT_MIBS_MIN;
    let memory_ok = match memory_hwm_delta_kib {
        Some(v) => v <= BUDGET_MEMORY_DELTA_KIB_MAX,
        None => true,
    };

    BudgetEvaluation {
        derive_avg_ms_max: BUDGET_DERIVE_AVG_MS_MAX,
        noise_avg_ms_max: BUDGET_NOISE_AVG_MS_MAX,
        throughput_mib_s_min: BUDGET_THROUGHPUT_MIBS_MIN,
        memory_delta_kib_max: BUDGET_MEMORY_DELTA_KIB_MAX,
        derive_ok,
        noise_ok,
        throughput_ok,
        memory_ok,
        all_ok: derive_ok && noise_ok && throughput_ok && memory_ok,
    }
}

#[cfg(target_os = "linux")]
fn memory_hwm_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?;
    kib.parse::<u64>().ok()
}

#[cfg(not(target_os = "linux"))]
fn memory_hwm_kib() -> Option<u64> {
    None
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
