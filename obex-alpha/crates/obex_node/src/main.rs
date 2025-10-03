#![forbid(unsafe_code)]
#![deny(warnings)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use subtle::ConstantTimeEq;
// use serde_json::json; // reserved for structured logs when puller is added
use hex::FromHex;
use obex_alpha_i::{decode_partrec, obex_verify_partrec, EcVrfVerifier, MAX_PARTREC_SIZE};
use obex_alpha_ii::{
    deserialize_header, obex_header_id, serialize_header, validate_header, Header,
    PartRootProvider, TicketRootProvider, TxRootProvider, OBEX_ALPHA_II_VERSION,
};
use obex_primitives::{constants, h_tag, le_bytes, merkle_root, Hash256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{RwLock, Semaphore};
type Db = sled::Db;

#[derive(Clone)]
#[allow(dead_code)]
struct AppState {
    // (slot, pk32) -> canonical ObexPartRec bytes
    partrecs: Arc<RwLock<HashMap<(u64, [u8; 32]), Vec<u8>>>>,
    // slot -> Vec<ticket leaf bytes>
    ticket_leaves: Arc<RwLock<HashMap<u64, Vec<Vec<u8>>>>>,
    // headers by slot
    headers: Arc<RwLock<HashMap<u64, Header>>>,
    db: Arc<Db>,
    metrics: Arc<Metrics>,
    sem_partrec: Arc<Semaphore>,
    sem_tickets: Arc<Semaphore>,
    peers: Arc<Vec<String>>,
    http_timeout_ms: u64,
}

const MAX_CONCURRENT_PARTREC_INGEST: usize = 16;
const MAX_CONCURRENT_TICKETS_INGEST: usize = 8;

struct Metrics {
    headers_validated_total: AtomicU64,
    headers_rejected_total: AtomicU64,
    header_validate_ms_total: AtomicU64,
    header_validate_count: AtomicU64,

    alpha_i_verify_ms_total: AtomicU64,
    alpha_i_verify_count: AtomicU64,

    root_build_ms_total: AtomicU64,
    root_build_count: AtomicU64,
    fetch_success_total: AtomicU64,
    fetch_fail_total: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            headers_validated_total: AtomicU64::new(0),
            headers_rejected_total: AtomicU64::new(0),
            header_validate_ms_total: AtomicU64::new(0),
            header_validate_count: AtomicU64::new(0),
            alpha_i_verify_ms_total: AtomicU64::new(0),
            alpha_i_verify_count: AtomicU64::new(0),
            root_build_ms_total: AtomicU64::new(0),
            root_build_count: AtomicU64::new(0),
            fetch_success_total: AtomicU64::new(0),
            fetch_fail_total: AtomicU64::new(0),
        }
    }
}

fn metrics_text(m: &Metrics) -> String {
    let hv = m.headers_validated_total.load(Ordering::Relaxed);
    let hr = m.headers_rejected_total.load(Ordering::Relaxed);
    let hv_ms = m.header_validate_ms_total.load(Ordering::Relaxed);
    let hv_cnt = m.header_validate_count.load(Ordering::Relaxed);
    let hv_avg = if hv_cnt == 0 { 0 } else { hv_ms / hv_cnt };

    let ai_ms = m.alpha_i_verify_ms_total.load(Ordering::Relaxed);
    let ai_cnt = m.alpha_i_verify_count.load(Ordering::Relaxed);
    let ai_avg = if ai_cnt == 0 { 0 } else { ai_ms / ai_cnt };

    let rb_ms = m.root_build_ms_total.load(Ordering::Relaxed);
    let rb_cnt = m.root_build_count.load(Ordering::Relaxed);
    let rb_avg = if rb_cnt == 0 { 0 } else { rb_ms / rb_cnt };
    let fsucc = m.fetch_success_total.load(Ordering::Relaxed);
    let ffail = m.fetch_fail_total.load(Ordering::Relaxed);

    format!(
        "# HELP obex_node_up 1\n# TYPE obex_node_up gauge\nobex_node_up 1\n\
         # HELP headers_validated_total count\n# TYPE headers_validated_total counter\nheaders_validated_total {}\n\
         # HELP headers_rejected_total count\n# TYPE headers_rejected_total counter\nheaders_rejected_total {}\n\
         # HELP header_validate_avg_ms average\n# TYPE header_validate_avg_ms gauge\nheader_validate_avg_ms {}\n\
         # HELP alpha_i_verify_avg_ms average\n# TYPE alpha_i_verify_avg_ms gauge\nalpha_i_verify_avg_ms {}\n\
         # HELP root_build_avg_ms average\n# TYPE root_build_avg_ms gauge\nroot_build_avg_ms {}\n\
         # HELP fetch_success_total count\n# TYPE fetch_success_total counter\nfetch_success_total {}\n\
         # HELP fetch_fail_total count\n# TYPE fetch_fail_total counter\nfetch_fail_total {}\n",
        hv, hr, hv_avg, ai_avg, rb_avg, fsucc, ffail
    )
}

fn log_json(level: &str, code: u32, msg: &str, extra: serde_json::Value) {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let obj = serde_json::json!({
        "ts_ms": ts,
        "level": level,
        "code": code,
        "msg": msg,
        "extra": extra,
    });
    println!("{}", obj);
}

fn decode_pk_hex(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err("pk hex must be 64 chars".to_owned());
    }
    let bytes = <[u8; 32]>::from_hex(s).map_err(|_| "invalid hex".to_owned())?;
    Ok(bytes)
}

async fn get_alpha_i_partrec(
    Path((slot, pk_hex)): Path<(u64, String)>,
    State(st): State<AppState>,
) -> Result<Response, (StatusCode, String)> {
    let pk = decode_pk_hex(&pk_hex).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let map = st.partrecs.read().await;
    let key = (slot, pk);
    let Some(bytes) = map.get(&key) else {
        return Err((StatusCode::NOT_FOUND, "not found".to_owned()));
    };
    if bytes.len() > MAX_PARTREC_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "partrec too large".to_owned(),
        ));
    }
    Ok((StatusCode::OK, bytes.clone()).into_response())
}

async fn get_alpha_iii_leaves(
    Path(slot): Path<u64>,
    State(st): State<AppState>,
) -> Result<Response, (StatusCode, String)> {
    let map = st.ticket_leaves.read().await;
    let Some(leaves) = map.get(&slot) else {
        return Err((StatusCode::NOT_FOUND, "not found".to_owned()));
    };
    let mut out = Vec::new();
    for leaf in leaves {
        out.extend_from_slice(leaf);
    }
    Ok((StatusCode::OK, out).into_response())
}

// POST /alpha_i/{slot}/{pk} — ingest canonical ObexPartRec bytes (size-capped and decodable)
async fn post_alpha_i_partrec(
    Path((slot, pk_hex)): Path<(u64, String)>,
    State(st): State<AppState>,
    body: axum::body::Bytes,
) -> Result<String, (StatusCode, String)> {
    let _permit = st
        .sem_partrec
        .acquire_owned()
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "busy".to_owned()))?;
    let pk = decode_pk_hex(&pk_hex).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let bytes = body.to_vec();
    if bytes.len() > MAX_PARTREC_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "partrec too large".to_owned(),
        ));
    }
    let rec = decode_partrec(&bytes)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "decode error".to_owned()))?;
    if rec.slot != slot {
        return Err((StatusCode::BAD_REQUEST, "slot mismatch".to_owned()));
    }
    // Persist
    st.partrecs.write().await.insert((slot, pk), bytes.clone());
    put_partrec_db(&st.db, slot, &pk, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok("ok".to_owned())
}

// POST /alpha_iii/{slot} — ingest concatenated ticket leaves (216-byte leaf size)
async fn post_alpha_iii_leaves(
    Path(slot): Path<u64>,
    State(st): State<AppState>,
    body: axum::body::Bytes,
) -> Result<String, (StatusCode, String)> {
    let _permit = st
        .sem_tickets
        .acquire_owned()
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "busy".to_owned()))?;
    const LEAF_LEN: usize = 216; // tag(32)+ticket_id(32)+txid(32)+sender(32)+nonce(8)+amount(16)+fee(16)+s_admit(8)+s_exec(8)+commit_hash(32)
    let buf = body.to_vec();
    if buf.len() % LEAF_LEN != 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "bad concatenation length".to_owned(),
        ));
    }
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(buf.len() / LEAF_LEN);
    let mut i = 0;
    while i < buf.len() {
        leaves.push(buf[i..i + LEAF_LEN].to_vec());
        i += LEAF_LEN;
    }
    st.ticket_leaves.write().await.insert(slot, leaves.clone());
    put_ticket_leaves_db(&st.db, slot, &buf).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok("ok".to_owned())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/alpha_i/:slot/:pk",
            get(get_alpha_i_partrec).post(post_alpha_i_partrec),
        )
        .route(
            "/alpha_iii/:slot",
            get(get_alpha_iii_leaves).post(post_alpha_iii_leaves),
        )
        .route("/header/:slot", get(get_header))
        .route("/header", post(post_header))
        .route("/advance", post(post_advance))
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .with_state(state)
}

#[derive(Parser, Debug)]
#[command(name = "obex-node")]
#[command(about = "OBEX Alpha node (testnet)", long_about = None)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    #[arg(long, default_value = "data/obex-node")]
    data_dir: String,
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,
    #[arg(long, default_value_t = MAX_CONCURRENT_PARTREC_INGEST)]
    max_partrec_concurrency: usize,
    #[arg(long, default_value_t = MAX_CONCURRENT_TICKETS_INGEST)]
    max_ticket_concurrency: usize,
    #[arg(long, default_value_t = 2000)]
    http_timeout_ms: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let db = sled::open(&args.data_dir).expect("db");
    let db = Arc::new(db);
    let state = AppState {
        db: db.clone(),
        partrecs: Arc::new(RwLock::new(HashMap::new())),
        ticket_leaves: Arc::new(RwLock::new(HashMap::new())),
        headers: Arc::new(RwLock::new(HashMap::new())),
        metrics: Arc::new(Metrics::new()),
        sem_partrec: Arc::new(Semaphore::new(args.max_partrec_concurrency)),
        sem_tickets: Arc::new(Semaphore::new(args.max_ticket_concurrency)),
        peers: Arc::new(args.peers.clone()),
        http_timeout_ms: args.http_timeout_ms,
    };
    // Load persisted headers
    if let Ok(Some(h0)) = get_header_db(&db, 0) {
        state.headers.write().await.insert(0, h0);
    } else {
        // Initialize genesis header at slot 0
        let y_core = [0u8; 32];
        let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
        let h0 = Header {
            parent_id: [0u8; 32],
            slot: 0,
            obex_version: OBEX_ALPHA_II_VERSION,
            seed_commit: h_tag(constants::TAG_SLOT_SEED, &[&[0u8; 32], &le_bytes::<8>(0)]),
            vdf_y_core: y_core,
            vdf_y_edge: y_edge,
            vdf_pi: vec![],
            vdf_ell: vec![],
            ticket_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
            part_root: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
            txroot_prev: h_tag(constants::TAG_MERKLE_EMPTY, &[]),
        };
        put_header_db(&db, &h0).expect("persist genesis");
        state.headers.write().await.insert(0, h0);
    }
    let app = router(state);
    let addr: SocketAddr = args.listen.parse().unwrap();
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

// Header GET
async fn get_header(
    Path(slot): Path<u64>,
    State(st): State<AppState>,
) -> Result<Json<HeaderDto>, (StatusCode, String)> {
    let map = st.headers.read().await;
    let Some(h) = map.get(&slot) else {
        return Err((StatusCode::NOT_FOUND, "not found".to_owned()));
    };
    Ok(Json(HeaderDto::from_header(h)))
}

// Header POST (accepts JSON; validates against current store and computes equalities)
#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct HeaderDto {
    parent_id: [u8; 32],
    slot: u64,
    obex_version: u32,
    seed_commit: [u8; 32],
    vdf_y_core: [u8; 32],
    vdf_y_edge: [u8; 32],
    vdf_pi: Vec<u8>,
    vdf_ell: Vec<u8>,
    ticket_root: [u8; 32],
    part_root: [u8; 32],
    txroot_prev: [u8; 32],
}

impl HeaderDto {
    fn into_header(self) -> Header {
        Header {
            parent_id: self.parent_id,
            slot: self.slot,
            obex_version: self.obex_version,
            seed_commit: self.seed_commit,
            vdf_y_core: self.vdf_y_core,
            vdf_y_edge: self.vdf_y_edge,
            vdf_pi: self.vdf_pi,
            vdf_ell: self.vdf_ell,
            ticket_root: self.ticket_root,
            part_root: self.part_root,
            txroot_prev: self.txroot_prev,
        }
    }
    fn from_header(h: &Header) -> Self {
        Self {
            parent_id: h.parent_id,
            slot: h.slot,
            obex_version: h.obex_version,
            seed_commit: h.seed_commit,
            vdf_y_core: h.vdf_y_core,
            vdf_y_edge: h.vdf_y_edge,
            vdf_pi: h.vdf_pi.clone(),
            vdf_ell: h.vdf_ell.clone(),
            ticket_root: h.ticket_root,
            part_root: h.part_root,
            txroot_prev: h.txroot_prev,
        }
    }
}

struct Providers<'a> {
    st: &'a AppState,
}
impl TicketRootProvider for Providers<'_> {
    fn compute_ticket_root(&self, slot: u64) -> Hash256 {
        futures::executor::block_on(ticket_root_for_slot(self.st, slot))
    }
}
impl PartRootProvider for Providers<'_> {
    fn compute_part_root(&self, slot: u64) -> Hash256 {
        futures::executor::block_on(part_root_for_slot(self.st, slot))
    }
}
impl TxRootProvider for Providers<'_> {
    fn compute_txroot(&self, slot: u64) -> Hash256 {
        // Compute txroot from ticket leaves at the given slot by
        // building a Merkle over Tag("obex.txid.leaf") || txid,
        // sorted by txid ascending.
        let map = futures::executor::block_on(self.st.ticket_leaves.read());
        let leaves_concat = map.get(&slot).cloned().unwrap_or_default();
        if leaves_concat.is_empty() {
            return h_tag(constants::TAG_MERKLE_EMPTY, &[]);
        }
        // Extract txids (bytes 64..96 in each leaf of length 216)
        let mut txids: Vec<[u8; 32]> = Vec::with_capacity(leaves_concat.len());
        for leaf in &leaves_concat {
            if leaf.len() < 96 {
                continue;
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&leaf[64..96]);
            txids.push(txid);
        }
        txids.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        txids.dedup();
        let txid_leaves: Vec<Vec<u8>> = txids
            .iter()
            .map(|xid| {
                let mut b = Vec::with_capacity(64);
                b.extend_from_slice(&h_tag(constants::TAG_TXID_LEAF, &[]));
                b.extend_from_slice(xid);
                b
            })
            .collect();
        merkle_root(&txid_leaves)
    }
}

async fn ticket_root_for_slot(st: &AppState, slot: u64) -> Hash256 {
    let t0 = Instant::now();
    let map = st.ticket_leaves.read().await;
    let leaves = map.get(&slot).cloned().unwrap_or_default();
    let root = merkle_root(&leaves);
    let dt_ms = t0.elapsed().as_millis() as u64;
    st.metrics
        .root_build_ms_total
        .fetch_add(dt_ms, Ordering::Relaxed);
    st.metrics
        .root_build_count
        .fetch_add(1, Ordering::Relaxed);
    root
}

async fn part_root_for_slot(st: &AppState, slot: u64) -> Hash256 {
    let t0 = Instant::now();
    let map = st.partrecs.read().await;
    let vrf = Rfc9381Vrf;
    let mut pks: Vec<[u8; 32]> = Vec::new();
    for ((s, _pk), bytes) in map.iter() {
        if *s != slot {
            continue;
        }
        if let Ok(rec) = decode_partrec(bytes) {
            // Need parent_id for alpha. Retrieve parent header.
            let parent_id = {
                let hdrs = st.headers.read().await;
                hdrs.get(&slot.wrapping_sub(1))
                    .map(|h| obex_header_id(h))
                    .unwrap_or([0u8; 32])
            };
            let t1 = Instant::now();
            if obex_verify_partrec(&rec, slot, &parent_id, &vrf) {
                let dt_ms = t1.elapsed().as_millis() as u64;
                st.metrics
                    .alpha_i_verify_ms_total
                    .fetch_add(dt_ms, Ordering::Relaxed);
                st.metrics
                    .alpha_i_verify_count
                    .fetch_add(1, Ordering::Relaxed);
                pks.push(rec.pk_ed25519);
            }
        }
    }
    pks.sort_unstable();
    pks.dedup();
    let leaves: Vec<Vec<u8>> = pks
        .iter()
        .map(|pk| {
            let mut b = Vec::with_capacity(64);
            b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[]));
            b.extend_from_slice(pk);
            b
        })
        .collect();
    let root = merkle_root(&leaves);
    let dt_ms = t0.elapsed().as_millis() as u64;
    st.metrics
        .root_build_ms_total
        .fetch_add(dt_ms, Ordering::Relaxed);
    st.metrics
        .root_build_count
        .fetch_add(1, Ordering::Relaxed);
    root
}

struct Rfc9381Vrf;
impl EcVrfVerifier for Rfc9381Vrf {
    fn verify(&self, vrf_pubkey: &[u8; 32], alpha: &Hash256, vrf_proof: &[u8]) -> Option<Vec<u8>> {
        if vrf_proof.len() != 80 {
            return None;
        }
        use sha2::Sha512;
        use vrf_rfc9381::{
            ec::edwards25519::{tai::EdVrfEdwards25519TaiPublicKey, EdVrfProof},
            Verifier as _,
        };
        let vk = EdVrfEdwards25519TaiPublicKey::from_slice(vrf_pubkey).ok()?;
        let mut pi80 = [0u8; 80];
        pi80.copy_from_slice(vrf_proof);
        let proof = <EdVrfProof as vrf_rfc9381::Proof<Sha512>>::decode_pi(&pi80).ok()?;
        let out = vk.verify(alpha, proof).ok()?;
        Some(out.as_slice().to_vec())
    }
}

async fn post_header(
    State(st): State<AppState>,
    Json(dto): Json<HeaderDto>,
) -> Result<String, (StatusCode, String)> {
    // must know parent
    let t0 = Instant::now();
    let parent_slot = dto
        .slot
        .checked_sub(1)
        .ok_or((StatusCode::BAD_REQUEST, "slot must be > 0".to_owned()))?;
    let parent = {
        let map = st.headers.read().await;
        map.get(&parent_slot).cloned().ok_or((
            StatusCode::PRECONDITION_FAILED,
            "parent header missing".to_owned(),
        ))?
    };
    // validate equalities
    let h = dto.clone().into_header();
    let providers = Providers { st: &st };
    let res = validate_header(
        &h,
        &parent,
        &providers,
        &providers,
        &providers,
        OBEX_ALPHA_II_VERSION,
    );
    let dt_ms = t0.elapsed().as_millis() as u64;
    st.metrics
        .header_validate_ms_total
        .fetch_add(dt_ms, Ordering::Relaxed);
    st.metrics
        .header_validate_count
        .fetch_add(1, Ordering::Relaxed);
    if let Err(e) = res {
        log_json(
            "warn",
            1000,
            "header_rejected",
            serde_json::json!({"slot": h.slot, "reason": format!("{:?}", e)})
        );
        st.metrics
            .headers_rejected_total
            .fetch_add(1, Ordering::Relaxed);
        return Err((StatusCode::UNPROCESSABLE_ENTITY, format!("{:?}", e)));
    } else {
        log_json(
            "info",
            1001,
            "header_accepted",
            serde_json::json!({"slot": h.slot})
        );
        st.metrics
            .headers_validated_total
            .fetch_add(1, Ordering::Relaxed);
    }
    st.headers.write().await.insert(h.slot, h);

    // Header-first pull: if roots are non-empty, fetch bodies to verify locally.
    let need_part = !bool::from(dto.part_root.ct_eq(&h_tag(constants::TAG_MERKLE_EMPTY, &[])));
    let need_tix = !bool::from(dto.ticket_root.ct_eq(&h_tag(constants::TAG_MERKLE_EMPTY, &[])));
    if need_part || need_tix {
        let peers = st.peers.clone();
        let timeout = st.http_timeout_ms;
        let slot = dto.slot;
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(timeout))
                .build()
                .expect("client");
            for base in peers.iter() {
                let base = base.trim_end_matches('/');
                let mut ok = true;
                if need_part {
                    // pull α‑I per unique pk is expensive; placeholder: pull nothing (requires index)
                }
                if need_tix {
                    let url = format!("{}/alpha_iii/{}", base, slot);
                    match client.get(url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.bytes().await {
                                Ok(bytes) => {
                                    log_json("info", 1100, "fetched_alpha_iii", serde_json::json!({"peer": base, "slot": slot, "len": bytes.len()}));
                                }
                                Err(e) => {
                                    ok = false;
                                    log_json("warn", 2101, "fetch_body_read_err", serde_json::json!({"peer": base, "slot": slot, "err": e.to_string()}));
                                }
                            }
                        }
                        Ok(resp) => {
                            ok = false;
                            log_json("warn", 2100, "fetch_body_http_err", serde_json::json!({"peer": base, "slot": slot, "status": resp.status().as_u16()}));
                        }
                        Err(e) => {
                            ok = false;
                            log_json("warn", 2102, "fetch_body_net_err", serde_json::json!({"peer": base, "slot": slot, "err": e.to_string()}));
                        }
                    }
                }
                if ok {
                    // success path
                }
            }
        });
    }
    put_header_db(&st.db, &dto.into_header())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok("ok".to_owned())
}

// Build and persist the next header deterministically from current state
async fn post_advance(State(st): State<AppState>) -> Result<Json<HeaderDto>, (StatusCode, String)> {
    // Find current max slot
    let (slot_max, parent) = {
        let map = st.headers.read().await;
        let Some((&mx, h)) = map.iter().max_by_key(|(k, _)| *k) else {
            return Err((StatusCode::PRECONDITION_FAILED, "no parent header".to_owned()));
        };
        (mx, h.clone())
    };
    let next_slot = slot_max.checked_add(1).ok_or((StatusCode::BAD_REQUEST, "slot overflow".to_owned()))?;
    let parent_id = obex_header_id(&parent);
    let seed_commit = h_tag(constants::TAG_SLOT_SEED, &[&parent_id, &le_bytes::<8>(u128::from(next_slot))]);
    let y_core = [3u8; 32];
    let y_edge = h_tag(constants::TAG_VDF_EDGE, &[&y_core]);
    // Compute roots from current store
    let providers = Providers { st: &st };
    let ticket_root = providers.compute_ticket_root(next_slot);
    let part_root = providers.compute_part_root(next_slot);
    let txroot_prev = providers.compute_txroot(slot_max);
    let h = Header {
        parent_id,
        slot: next_slot,
        obex_version: OBEX_ALPHA_II_VERSION,
        seed_commit,
        vdf_y_core: y_core,
        vdf_y_edge: y_edge,
        vdf_pi: vec![],
        vdf_ell: vec![],
        ticket_root,
        part_root,
        txroot_prev,
    };
    let t0 = Instant::now();
    validate_header(&h, &parent, &providers, &providers, &providers, OBEX_ALPHA_II_VERSION)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{:?}", e)))?;
    log_json(
        "info",
        1002,
        "header_built",
        serde_json::json!({"slot": h.slot})
    );
    let dt_ms = t0.elapsed().as_millis() as u64;
    st.metrics
        .header_validate_ms_total
        .fetch_add(dt_ms, Ordering::Relaxed);
    st.metrics
        .header_validate_count
        .fetch_add(1, Ordering::Relaxed);
    st.metrics
        .headers_validated_total
        .fetch_add(1, Ordering::Relaxed);
    st.headers.write().await.insert(h.slot, h.clone());
    put_header_db(&st.db, &h).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(HeaderDto::from_header(&h)))
}

fn put_header_db(db: &Db, h: &Header) -> Result<(), String> {
    let key = header_key(h.slot);
    let val = serialize_header(h);
    db.insert(key, val).map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn get_header_db(db: &Db, slot: u64) -> Result<Option<Header>, String> {
    let key = header_key(slot);
    if let Some(ivec) = db.get(key).map_err(|e| e.to_string())? {
        let bytes = ivec.to_vec();
        let h = deserialize_header(&bytes).map_err(|_| "decode header".to_owned())?;
        Ok(Some(h))
    } else {
        Ok(None)
    }
}

fn header_key(slot: u64) -> [u8; 8] {
    u64::to_le_bytes(slot)
}

fn put_partrec_db(db: &Db, slot: u64, pk: &[u8; 32], bytes: &[u8]) -> Result<(), String> {
    let mut key = Vec::with_capacity(8 + 32 + 4);
    key.extend_from_slice(&u64::to_le_bytes(slot));
    key.extend_from_slice(pk);
    key.extend_from_slice(b"part");
    db.insert(key, bytes).map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn put_ticket_leaves_db(db: &Db, slot: u64, concat: &[u8]) -> Result<(), String> {
    let mut key = Vec::with_capacity(8 + 5);
    key.extend_from_slice(&u64::to_le_bytes(slot));
    key.extend_from_slice(b"tixls");
    db.insert(key, concat).map_err(|e| e.to_string())?;
    db.flush().map_err(|e| e.to_string())?;
    Ok(())
}

async fn metrics(State(st): State<AppState>) -> String {
    metrics_text(&st.metrics)
}

async fn healthz(State(st): State<AppState>) -> Result<String, (StatusCode, String)> {
    let has_genesis = { st.headers.read().await.contains_key(&0) };
    if !has_genesis {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "missing genesis".to_owned()));
    }
    Ok("ok".to_owned())
}
