#![forbid(unsafe_code)]
#![deny(warnings)]

use axum::{
    extract::{Path, Query, State},
    http::{StatusCode, HeaderMap, header},
    response::{IntoResponse, Response},
    response::sse::{Event as SseEvent, Sse},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::compression::CompressionLayer;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
// ed25519 key verification for wallet endpoints will be wired when POST /v1/tx is added
use clap::Parser;
use subtle::ConstantTimeEq;
// use serde_json::json; // reserved for structured logs when puller is added
use hex::FromHex;
use obex_alpha_i::{decode_partrec, obex_verify_partrec, EcVrfVerifier, MAX_PARTREC_SIZE};
use obex_alpha_ii::{
    deserialize_header, obex_header_id, serialize_header, validate_header, Header,
    PartRootProvider, TicketRootProvider, TxRootProvider, OBEX_ALPHA_II_VERSION,
};
use obex_alpha_ii::ValidateErr;
use obex_primitives::{constants, h_tag, le_bytes, merkle_root, merkle_leaf, merkle_node, Hash256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as TokioStreamExt;
// no extra stream imports needed
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
type Db = sled::Db;

#[derive(Clone)]
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
    per_peer_limit: usize,
    backoff_base_ms: u64,
    backoff_max_ms: u64,
    ban_threshold: u32,
    ban_duration_ms: u64,
    peer_state: Arc<RwLock<HashMap<String, PeerState>>>,
    peer_limits: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
    reject_counts: Arc<RwLock<HashMap<&'static str, u64>>>,
    network_id: String,
    evt_tx: broadcast::Sender<String>,
    // indices for explorer/wallet UX
    tx_index: Arc<RwLock<HashMap<[u8;32], (u64, Vec<u8>)>>>,
    // minimal ledger state
    spendable: Arc<RwLock<HashMap<[u8;32], u128>>>,
    reserved: Arc<RwLock<HashMap<[u8;32], u128>>>,
    next_nonce: Arc<RwLock<HashMap<[u8;32], u64>>>,
    tx_status: Arc<RwLock<HashMap<[u8;32], &'static str>>>,
}

#[derive(Clone, Default)]
struct PeerState {
    successes: u64,
    failures: u64,
    next_allowed_ms: u128,
    banned_until_ms: u128,
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
    fetch_ms_total: AtomicU64,
    fetch_count: AtomicU64,
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
            fetch_ms_total: AtomicU64::new(0),
            fetch_count: AtomicU64::new(0),
        }
    }
}

// ---------- V1 DTOs and helpers ----------

#[derive(Debug, serde::Serialize)]
struct ApiErrorBody {
    code: u32,
    error: String,
    message: String,
    details: serde_json::Value,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
}

impl ApiError {
    fn new(status: StatusCode, code: u32, error: &str, message: impl Into<String>, details: serde_json::Value) -> Self {
        Self { status, body: ApiErrorBody { code, error: error.to_owned(), message: message.into(), details } }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let s = self.status;
        let body = Json(self.body);
        (s, body).into_response()
    }
}

#[allow(dead_code)]
fn json_with_etag<T: serde::Serialize>(req_headers: &HeaderMap, value: &T) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_default();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let etag_val = format!("\"{}\"", hex::encode(hasher.finalize()));
    if let Some(tag) = req_headers.get(header::IF_NONE_MATCH) {
        if let Ok(tag_str) = tag.to_str() {
            if tag_str.trim() == etag_val {
                return Response::builder().status(StatusCode::NOT_MODIFIED)
                    .header(header::CACHE_CONTROL, "public, max-age=5")
                    .body(axum::body::Body::empty()).unwrap();
            }
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag_val)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "public, max-age=5")
        .body(axum::body::Body::from(body))
        .unwrap()
}

#[derive(serde::Serialize)]
struct InfoDto<'a> {
    chain_id: &'a str,
    genesis_hash: String,
    obex_version: u32,
    slots_per_sec: u64,
    head: Option<HeadDto>,
    address_format: &'a str,
}

#[derive(serde::Serialize)]
struct HeadDto {
    slot: u64,
    header_id: String,
}

#[derive(serde::Serialize)]
struct HeaderViewDto {
    parent_id: String,
    slot: u64,
    obex_version: u32,
    seed_commit: String,
    vdf_y_core: String,
    vdf_y_edge: String,
    vdf_pi: String,
    vdf_ell: String,
    ticket_root: String,
    part_root: String,
    txroot_prev: String,
    header_id: String,
}

fn hex32(x: &Hash256) -> String { format!("0x{}", hex::encode(x)) }
fn hex_bytes(b: &[u8]) -> String { format!("0x{}", hex::encode(b)) }

fn header_to_dto(h: &Header) -> HeaderViewDto {
    let hid = obex_header_id(h);
    HeaderViewDto {
        parent_id: hex32(&h.parent_id),
        slot: h.slot,
        obex_version: h.obex_version,
        seed_commit: hex32(&h.seed_commit),
        vdf_y_core: hex32(&h.vdf_y_core),
        vdf_y_edge: hex32(&h.vdf_y_edge),
        vdf_pi: hex_bytes(&h.vdf_pi),
        vdf_ell: hex_bytes(&h.vdf_ell),
        ticket_root: hex32(&h.ticket_root),
        part_root: hex32(&h.part_root),
        txroot_prev: hex32(&h.txroot_prev),
        header_id: hex32(&hid),
    }
}

#[derive(Default)]
struct PageParams { limit: Option<usize>, from: Option<u64>, to: Option<u64> }

fn parse_page(q: &std::collections::HashMap<String, String>) -> PageParams {
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok());
    let from = q.get("from").and_then(|s| s.parse::<u64>().ok());
    let to = q.get("to").and_then(|s| s.parse::<u64>().ok());
    PageParams { limit, from, to }
}

// ---------- V1 Handlers ----------

async fn v1_info(headers: HeaderMap, State(st): State<AppState>) -> Result<Response, ApiError> {
    let genesis = st.headers.read().await.get(&0).cloned();
    let head = st.headers.read().await.keys().max().cloned();
    let head_obj = if let Some(s) = head { st.headers.read().await.get(&s).cloned() } else { None };
    let head_dto = head_obj.map(|h| HeadDto { slot: h.slot, header_id: hex32(&obex_header_id(&h)) });
    let genesis_hash = genesis.map(|h| hex32(&obex_header_id(&h))).unwrap_or_else(|| "0x".to_owned());
    let dto = InfoDto {
        chain_id: Box::leak(st.network_id.clone().into_boxed_str()),
        genesis_hash,
        obex_version: OBEX_ALPHA_II_VERSION,
        slots_per_sec: 1_000 / obex_alpha_t::SLOT_MS,
        head: head_dto,
        address_format: "ed25519-hex",
    };
    Ok(json_with_etag(&headers, &dto))
}

async fn v1_head(headers: HeaderMap, State(st): State<AppState>) -> Result<Response, ApiError> {
    let hdrs = st.headers.read().await;
    let Some((&slot, h)) = hdrs.iter().max_by_key(|(k, _)| *k) else { return Err(ApiError::new(StatusCode::NOT_FOUND, 40401, "not_found", "no head", serde_json::json!({}))); };
    let dto = HeadDto { slot, header_id: hex32(&obex_header_id(h)) };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct HeadersPage { items: Vec<HeaderViewDto>, next_cursor: Option<String> }

async fn v1_headers_range(
    headers: HeaderMap,
    State(st): State<AppState>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let params = parse_page(&q);
    let limit = params.limit.unwrap_or(100).min(500);
    let from = params.from.unwrap_or(0);
    let to = params.to.unwrap_or(u64::MAX);
    let start = if let Some(cur) = q.get("cursor") { base64::engine::general_purpose::STANDARD.decode(cur).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0) } else { 0 };
    let hdrs = st.headers.read().await;
    let mut slots: Vec<u64> = hdrs.keys().cloned().filter(|s| *s >= from && *s <= to).collect();
    slots.sort_unstable();
    let mut items = Vec::new();
    let mut iter = slots.into_iter().skip(start);
    for s in (&mut iter).take(limit) {
        if let Some(h) = hdrs.get(&s) { items.push(header_to_dto(h)); }
    }
    let next_idx = start + items.len();
    let more = iter.next().is_some();
    let next_cursor = if more { Some(base64::engine::general_purpose::STANDARD.encode(next_idx.to_string())) } else { None };
    let dto = HeadersPage { items, next_cursor };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct SlotSummary { slot: u64, header: HeaderViewDto, counts: CountsDto }
#[derive(serde::Serialize)]
struct CountsDto { tickets: usize, participants: usize }

async fn v1_slot_summary(headers: HeaderMap, Path(slot): Path<u64>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let hdrs = st.headers.read().await;
    let Some(h) = hdrs.get(&slot) else { return Err(ApiError::new(StatusCode::NOT_FOUND, 40401, "not_found", "slot not found", serde_json::json!({"slot": slot}))); };
    let tickets = st.ticket_leaves.read().await.get(&slot).map(|v| v.len()).unwrap_or(0);
    let participants = st.partrecs.read().await.keys().filter(|(s, _)| *s == slot).count();
    let dto = SlotSummary { slot, header: header_to_dto(h), counts: CountsDto { tickets, participants } };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct TicketsPage { slot: u64, items: Vec<TicketView>, next_cursor: Option<String> }
#[derive(serde::Serialize)]
struct TicketView {
    ticket_id: String, txid: String, sender: String, nonce: u64, amount_u: String, fee_u: String, s_admit: u64, s_exec: u64, commit_hash: String,
}

async fn v1_alpha_iii_json(headers: HeaderMap, Path(slot): Path<u64>, State(st): State<AppState>, Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Response, ApiError> {
    let limit = q.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(100).min(500);
    let start = if let Some(cur) = q.get("cursor") { base64::engine::general_purpose::STANDARD.decode(cur).ok().and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0) } else { 0 };
    let leaves = st.ticket_leaves.read().await.get(&slot).cloned().unwrap_or_default();
    let mut items = Vec::new();
    let mut iter = leaves.into_iter().skip(start);
    for leaf in (&mut iter).take(limit) {
        if leaf.len() != 216 { continue; }
        let ticket_id = &leaf[32..64];
        let txid = &leaf[64..96];
        let sender = &leaf[96..128];
        let nonce = u64::from_le_bytes(leaf[128..136].try_into().unwrap());
        let amount_u = u128::from_le_bytes(leaf[136..152].try_into().unwrap());
        let fee_u = u128::from_le_bytes(leaf[152..168].try_into().unwrap());
        let s_admit = u64::from_le_bytes(leaf[168..176].try_into().unwrap());
        let s_exec = u64::from_le_bytes(leaf[176..184].try_into().unwrap());
        let commit_hash = &leaf[184..216-0];
        // Index tx for later lookup
        let mut key = [0u8;32]; key.copy_from_slice(txid);
        st.tx_index.write().await.insert(key, (slot, leaf.clone()));
        // mark admitted
        let mut k2 = [0u8;32]; k2.copy_from_slice(txid);
        st.tx_status.write().await.insert(k2, "admitted");
        items.push(TicketView {
            ticket_id: format!("0x{}", hex::encode(ticket_id)),
            txid: format!("0x{}", hex::encode(txid)),
            sender: format!("0x{}", hex::encode(sender)),
            nonce,
            amount_u: amount_u.to_string(),
            fee_u: fee_u.to_string(),
            s_admit,
            s_exec,
            commit_hash: format!("0x{}", hex::encode(commit_hash)),
        });
        // update naive ledger indices
        let mut pk = [0u8;32]; pk.copy_from_slice(sender);
        let mut nn = st.next_nonce.write().await;
        let cur = nn.get(&pk).copied().unwrap_or(0);
        let cand = nonce.saturating_add(1);
        if cand > cur { nn.insert(pk, cand); }
        // naive spendable: increase sender by -(amount+fee) is unknown without prior balances; keep 0 for now
    }
    let next_idx = start + items.len();
    let more = iter.next().is_some();
    let next_cursor = if more { Some(base64::engine::general_purpose::STANDARD.encode(next_idx.to_string())) } else { None };
    let dto = TicketsPage { slot, items, next_cursor };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct AlphaIIndexJson { slot: u64, participants: Vec<String>, count: usize }

async fn v1_alpha_i_index_json(headers: HeaderMap, Path(slot): Path<u64>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let map = st.partrecs.read().await;
    let mut v = Vec::new();
    for ((s, pk), _) in map.iter() { if *s == slot { v.push(format!("0x{}", hex::encode(pk))); } }
    v.sort(); v.dedup();
    let count = v.len();
    let dto = AlphaIIndexJson { slot, participants: v, count };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct ProofDto { leaf: String, siblings: Vec<String>, index: u64, root: String }

async fn v1_proof_ticket(headers: HeaderMap, Path((slot, txid_hex)): Path<(u64, String)>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let leaves = st.ticket_leaves.read().await.get(&slot).cloned().unwrap_or_default();
    if leaves.is_empty() { return Err(ApiError::new(StatusCode::NOT_FOUND, 40402, "not_found", "no leaves for slot", serde_json::json!({"slot": slot}))); }
    let txid_bytes = hex::decode(txid_hex.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40001, "bad_request", "bad txid", serde_json::json!({})))?;
    let mut idx = None;
    for (i, leaf) in leaves.iter().enumerate() {
        if leaf.len() != 216 { continue; }
        if &leaf[64..96] == txid_bytes.as_slice() { idx = Some(i as u64); break; }
    }
    let Some(mut index) = idx else { return Err(ApiError::new(StatusCode::NOT_FOUND, 40403, "not_found", "txid not in slot", serde_json::json!({"slot": slot}))); };
    // Build path with duplicate-last rule
    let mut level: Vec<Hash256> = leaves.iter().map(|p| merkle_leaf(p)).collect();
    let mut siblings: Vec<String> = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 { if let Some(last) = level.last().copied() { level.push(last); } }
        let mut next: Vec<Hash256> = Vec::with_capacity((level.len()+1)/2);
        let mut i = 0usize;
        while i < level.len() {
            let l = level[i]; let r = level[i+1];
            if i as u64 == (index & !1) { // sibling at this pair
                if index & 1 == 0 { siblings.push(format!("0x{}", hex::encode(r))); } else { siblings.push(format!("0x{}", hex::encode(l))); }
                index >>= 1;
            }
            next.push(merkle_node(&l, &r));
            i += 2;
        }
        level = next;
    }
    let root = level[0];
    let leaf = &leaves[idx.unwrap() as usize];
    let dto = ProofDto { leaf: hex_bytes(leaf), siblings, index: idx.unwrap(), root: hex32(&root) };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct TicketResolve { slot: u64, ticket: TicketView, proof: ProofDto }

async fn v1_ticket_by_txid(headers: HeaderMap, Path(txid_hex): Path<String>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let txid_bytes = hex::decode(txid_hex.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40001, "bad_request", "bad txid", serde_json::json!({})))?;
    if txid_bytes.len() != 32 { return Err(ApiError::new(StatusCode::BAD_REQUEST, 40001, "bad_request", "bad txid", serde_json::json!({}))); }
    let mut key = [0u8;32]; key.copy_from_slice(&txid_bytes);
    let (slot, leaf) = st.tx_index.read().await.get(&key).cloned().ok_or(ApiError::new(StatusCode::NOT_FOUND, 40406, "not_found", "unknown txid", serde_json::json!({})))?;
    // Build TicketView
    let sender = &leaf[96..128];
    let nonce = u64::from_le_bytes(leaf[128..136].try_into().unwrap());
    let amount_u = u128::from_le_bytes(leaf[136..152].try_into().unwrap());
    let fee_u = u128::from_le_bytes(leaf[152..168].try_into().unwrap());
    let s_admit = u64::from_le_bytes(leaf[168..176].try_into().unwrap());
    let s_exec = u64::from_le_bytes(leaf[176..184].try_into().unwrap());
    let commit_hash = &leaf[184..216];
    let tv = TicketView {
        ticket_id: format!("0x{}", hex::encode(&leaf[32..64])),
        txid: format!("0x{}", hex::encode(&leaf[64..96])),
        sender: format!("0x{}", hex::encode(sender)),
        nonce,
        amount_u: amount_u.to_string(),
        fee_u: fee_u.to_string(),
        s_admit,
        s_exec,
        commit_hash: format!("0x{}", hex::encode(commit_hash)),
    };
    // Proof reuse
    let proof = {
        let leaves = st.ticket_leaves.read().await.get(&slot).cloned().unwrap_or_default();
        if leaves.is_empty() { return Err(ApiError::new(StatusCode::NOT_FOUND, 40402, "not_found", "no leaves for slot", serde_json::json!({"slot": slot}))); }
        let mut idx = None;
        for (i, l) in leaves.iter().enumerate() { if l.len()==216 && &l[64..96]==txid_bytes.as_slice() { idx=Some(i as u64); break; } }
        let Some(mut index)=idx else { return Err(ApiError::new(StatusCode::NOT_FOUND, 40403, "not_found", "txid not in slot", serde_json::json!({"slot": slot}))); };
        let mut level: Vec<Hash256> = leaves.iter().map(|p| merkle_leaf(p)).collect();
        let mut siblings: Vec<String> = Vec::new();
        while level.len()>1 { if level.len()%2==1 { if let Some(last)=level.last().copied(){ level.push(last);} } let mut next:Vec<Hash256>=Vec::with_capacity((level.len()+1)/2); let mut i=0usize; while i<level.len(){ let l=level[i]; let r=level[i+1]; if i as u64 == (index & !1) { if index & 1 == 0 { siblings.push(format!("0x{}", hex::encode(r))); } else { siblings.push(format!("0x{}", hex::encode(l))); } index >>= 1; } next.push(merkle_node(&l,&r)); i+=2;} level=next; }
        let root = level[0];
        ProofDto { leaf: hex_bytes(&leaf), siblings, index: idx.unwrap(), root: hex32(&root) }
    };
    let dto = TicketResolve { slot, ticket: tv, proof };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct PeersDto { count: usize, peers: Vec<String> }

async fn v1_peers(headers: HeaderMap, State(st): State<AppState>) -> Result<Response, ApiError> {
    let peers = st.peers.iter().cloned().collect::<Vec<_>>();
    let dto = PeersDto { count: peers.len(), peers };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct AccountDto { pk: String, spendable_u: String, reserved_u: String, next_nonce: u64 }

async fn v1_account(headers: HeaderMap, Path(pk_hex): Path<String>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let pk = decode_pk_hex(&pk_hex).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, 40002, "bad_request", e, serde_json::json!({})))?;
    let sp = st.spendable.read().await.get(&pk).copied().unwrap_or(0);
    let rv = st.reserved.read().await.get(&pk).copied().unwrap_or(0);
    let nn = st.next_nonce.read().await.get(&pk).copied().unwrap_or(0);
    let dto = AccountDto { pk: format!("0x{}", hex::encode(pk)), spendable_u: sp.to_string(), reserved_u: rv.to_string(), next_nonce: nn };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct TxStatusDto { txid: String, status: String, slot: Option<u64> }

async fn v1_tx_status(headers: HeaderMap, Path(txid_hex): Path<String>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let bytes = hex::decode(txid_hex.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40001, "bad_request", "bad txid", serde_json::json!({})))?;
    if bytes.len()!=32 { return Err(ApiError::new(StatusCode::BAD_REQUEST, 40001, "bad_request", "bad txid", serde_json::json!({}))); }
    let mut k = [0u8;32]; k.copy_from_slice(&bytes);
    let status = st.tx_status.read().await.get(&k).copied().unwrap_or("unknown");
    let slot = st.tx_index.read().await.get(&k).map(|(s, _)| *s);
    let dto = TxStatusDto { txid: format!("0x{}", hex::encode(bytes)), status: status.to_owned(), slot };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Deserialize)]
struct TxSubmitBody {
    tx_body_v1: serde_json::Value,
    signature: String,
}

#[derive(serde::Serialize)]
struct TxSubmitResp { txid: String, commit_hash: String, accepted: bool, reason: Option<String> }

async fn v1_tx_submit(State(st): State<AppState>, Json(body): Json<TxSubmitBody>) -> Result<Json<TxSubmitResp>, ApiError> {
    // Verify signature over canonical bytes TAG_TX_SIG||canonical_tx_bytes(tx)
    let sig_bytes = hex::decode(body.signature.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40010, "bad_request", "bad signature hex", serde_json::json!({})))?;
    if sig_bytes.len()!=64 { return Err(ApiError::new(StatusCode::BAD_REQUEST, 40010, "bad_request", "bad signature length", serde_json::json!({}))); }
    // Map JSON into TxBodyV1 strictly
    #[derive(serde::Deserialize)]
    struct TxIn {
        sender: String, recipient: String, nonce: u64, amount_u: String, fee_u: String, s_bind: u64, y_bind: String,
        #[serde(default)]
        memo: String,
    }
    let tx_in: TxIn = serde_json::from_value(body.tx_body_v1.clone()).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40011, "bad_request", "tx body invalid", serde_json::json!({})))?;
    let sender_pk = hex::decode(tx_in.sender.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40012, "bad_request", "sender hex", serde_json::json!({})))?;
    if sender_pk.len()!=32 { return Err(ApiError::new(StatusCode::BAD_REQUEST, 40012, "bad_request", "sender len", serde_json::json!({}))); }
    // Construct canonical tx bytes using α‑III helpers
    use obex_alpha_iii::{TxBodyV1, AccessList, txid as txid_fn, tx_commit as commit_fn};
    let mut sender32=[0u8;32]; sender32.copy_from_slice(&sender_pk);
    let recipient_pk = hex::decode(tx_in.recipient.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40013, "bad_request", "recipient hex", serde_json::json!({})))?;
    if recipient_pk.len()!=32 { return Err(ApiError::new(StatusCode::BAD_REQUEST, 40013, "bad_request", "recipient len", serde_json::json!({}))); }
    let mut recipient32=[0u8;32]; recipient32.copy_from_slice(&recipient_pk);
    let y_bind_bytes = hex::decode(tx_in.y_bind.trim_start_matches("0x")).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40014, "bad_request", "y_bind hex", serde_json::json!({})))?;
    if y_bind_bytes.len()!=32 { return Err(ApiError::new(StatusCode::BAD_REQUEST, 40014, "bad_request", "y_bind len", serde_json::json!({}))); }
    let mut y_bind=[0u8;32]; y_bind.copy_from_slice(&y_bind_bytes);
    let amount_u = tx_in.amount_u.parse::<u128>().map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40015, "bad_request", "amount_u", serde_json::json!({})))?;
    let fee_u = tx_in.fee_u.parse::<u128>().map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40016, "bad_request", "fee_u", serde_json::json!({})))?;
    let tx = TxBodyV1 {
        sender: sender32,
        recipient: recipient32,
        nonce: tx_in.nonce,
        amount_u,
        fee_u,
        s_bind: tx_in.s_bind,
        y_bind,
        access: AccessList { read_accounts: vec![], write_accounts: vec![] },
        memo: hex::decode(tx_in.memo.trim_start_matches("0x")).unwrap_or_default(),
    };
    let msg = obex_primitives::h_tag(obex_primitives::constants::TAG_TX_SIG, &[&obex_alpha_iii::canonical_tx_bytes(&tx)]);
    let vk = Ed25519VerifyingKey::from_bytes(&sender32).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40017, "bad_request", "sender vk", serde_json::json!({})))?;
    let sig = Ed25519Signature::from_slice(&sig_bytes).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, 40010, "bad_request", "sig parse", serde_json::json!({})))?;
    if vk.verify_strict(&msg, &sig).is_err() {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, 42201, "invalid_sig", "signature verify failed", serde_json::json!({})));
    }
    let xid = txid_fn(&tx);
    let ch = commit_fn(&tx);
    let mut k = [0u8;32]; k.copy_from_slice(&xid);
    st.tx_status.write().await.insert(k, "pending");
    Ok(Json(TxSubmitResp { txid: format!("0x{}", hex::encode(xid)), commit_hash: format!("0x{}", hex::encode(ch)), accepted: true, reason: None }))
}

async fn v1_proof_participant(headers: HeaderMap, Path((slot, pk_hex)): Path<(u64, String)>, State(st): State<AppState>) -> Result<Response, ApiError> {
    let pk = decode_pk_hex(&pk_hex).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, 40002, "bad_request", e, serde_json::json!({})))?;
    let map = st.partrecs.read().await;
    let mut pks: Vec<[u8;32]> = map.iter().filter_map(|((s, k), _)| if *s == slot { Some(*k) } else { None }).collect();
    if pks.is_empty() { return Err(ApiError::new(StatusCode::NOT_FOUND, 40404, "not_found", "no participants", serde_json::json!({"slot": slot}))); }
    pks.sort_unstable(); pks.dedup();
    let mut idx = None;
    let leaves: Vec<Vec<u8>> = pks.iter().map(|k| { let mut b = Vec::with_capacity(64); b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[])); b.extend_from_slice(k); b }).collect();
    for (i, k) in pks.iter().enumerate() { if *k == pk { idx = Some(i as u64); break; } }
    let Some(mut index) = idx else { return Err(ApiError::new(StatusCode::NOT_FOUND, 40405, "not_found", "pk not in slot", serde_json::json!({"slot": slot}))); };
    let mut level: Vec<Hash256> = leaves.iter().map(|p| merkle_leaf(p)).collect();
    let mut siblings: Vec<String> = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 { if let Some(last) = level.last().copied() { level.push(last); } }
        let mut next: Vec<Hash256> = Vec::with_capacity((level.len()+1)/2);
        let mut i = 0usize;
        while i < level.len() {
            let l = level[i]; let r = level[i+1];
            if i as u64 == (index & !1) {
                if index & 1 == 0 { siblings.push(format!("0x{}", hex::encode(r))); } else { siblings.push(format!("0x{}", hex::encode(l))); }
                index >>= 1;
            }
            next.push(merkle_node(&l, &r));
            i += 2;
        }
        level = next;
    }
    let root = level[0];
    let mut leaf = Vec::with_capacity(64); leaf.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[])); leaf.extend_from_slice(&pk);
    let dto = ProofDto { leaf: hex_bytes(&leaf), siblings, index: idx.unwrap(), root: hex32(&root) };
    Ok(json_with_etag(&headers, &dto))
}

// --- Search and Stats ---

#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum SearchResult {
    #[serde(rename = "header")] Header { slot: u64, header_id: String },
    #[serde(rename = "tx")] Tx { slot: u64, txid: String },
    #[serde(rename = "account")] Account { pk: String },
    #[serde(rename = "slot")] Slot { slot: u64 },
}

#[derive(serde::Serialize)]
struct SearchDto { query: String, result: Option<SearchResult> }

async fn v1_search(headers: HeaderMap, State(st): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let qstr = q.get("q").cloned().unwrap_or_default();
    // Try slot
    if let Ok(s) = qstr.parse::<u64>() {
        if st.headers.read().await.contains_key(&s) {
            let dto = SearchDto { query: qstr, result: Some(SearchResult::Slot { slot: s }) };
            return Ok(json_with_etag(&headers, &dto));
        }
    }
    let hexs = qstr.trim_start_matches("0x");
    if hexs.len() == 64 {
        // could be header_id/txid/pk
        let bytes = match hex::decode(hexs) { Ok(b) => b, Err(_) => Vec::new() };
        if bytes.len() == 32 {
            // header?
            for (s, h) in st.headers.read().await.iter() {
                if obex_header_id(h) == bytes.as_slice() { let dto = SearchDto { query: qstr, result: Some(SearchResult::Header { slot: *s, header_id: format!("0x{}", hex::encode(&bytes)) }) }; return Ok(json_with_etag(&headers, &dto)); }
            }
            // tx?
            for (s, leaves) in st.ticket_leaves.read().await.iter() {
                if leaves.iter().any(|leaf| leaf.len()==216 && &leaf[64..96]==bytes.as_slice()) {
                    let dto = SearchDto { query: qstr, result: Some(SearchResult::Tx { slot: *s, txid: format!("0x{}", hex::encode(&bytes)) }) }; return Ok(json_with_etag(&headers, &dto));
                }
            }
            // account?
            for ((_s, pk), _) in st.partrecs.read().await.iter() {
                if pk == &<[u8;32]>::try_from(bytes.as_slice()).unwrap() { let dto = SearchDto { query: qstr, result: Some(SearchResult::Account { pk: format!("0x{}", hex::encode(pk)) }) }; return Ok(json_with_etag(&headers, &dto)); }
            }
        }
    }
    let dto = SearchDto { query: qstr, result: None };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct SupplyStats { slots_elapsed: u64, scheduled_emitted_u: String, total_supply_u: String, halving_period_years: u64 }

async fn v1_stats_supply(headers: HeaderMap, State(st): State<AppState>) -> Result<Response, ApiError> {
    let slots_elapsed = st.headers.read().await.keys().max().copied().unwrap_or(0);
    let dto = SupplyStats { slots_elapsed, scheduled_emitted_u: "0".to_owned(), total_supply_u: obex_alpha_t::TOTAL_SUPPLY_UOBX.to_string(), halving_period_years: obex_alpha_t::YEARS_PER_HALVING };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct ParticipationItem { slot: u64, count: usize }
#[derive(serde::Serialize)]
struct ParticipationStats { items: Vec<ParticipationItem> }

async fn v1_stats_participation(headers: HeaderMap, State(st): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let from = q.get("from").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let to = q.get("to").and_then(|s| s.parse::<u64>().ok()).unwrap_or(u64::MAX);
    let mut items = Vec::new();
    let hdrs = st.headers.read().await;
    for s in hdrs.keys().cloned().filter(|s| *s>=from && *s<=to) {
        let c = st.partrecs.read().await.keys().filter(|(ss, _)| *ss==s).count();
        items.push(ParticipationItem { slot: s, count: c });
    }
    let dto = ParticipationStats { items };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct FeesItem { slot: u64, total_fees_u: String }
#[derive(serde::Serialize)]
struct FeesStats { items: Vec<FeesItem> }

async fn v1_stats_fees(headers: HeaderMap, State(st): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let from = q.get("from").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let to = q.get("to").and_then(|s| s.parse::<u64>().ok()).unwrap_or(u64::MAX);
    let mut items = Vec::new();
    let hdrs = st.headers.read().await;
    for s in hdrs.keys().cloned().filter(|s| *s>=from && *s<=to) {
        // fees are not tracked yet; return 0 for now
        items.push(FeesItem { slot: s, total_fees_u: "0".to_owned() });
    }
    let dto = FeesStats { items };
    Ok(json_with_etag(&headers, &dto))
}

#[derive(serde::Serialize)]
struct FeesRule { min_tx_u: String, flat_switch_u: String, flat_fee_u: String, rule: &'static str }

async fn v1_fees(headers: HeaderMap) -> Result<Response, ApiError> {
    let dto = FeesRule {
        min_tx_u: obex_alpha_iii::MIN_TX_U.to_string(),
        flat_switch_u: obex_alpha_iii::FLAT_SWITCH_U.to_string(),
        flat_fee_u: obex_alpha_iii::FLAT_FEE_U.to_string(),
        rule: "flat-or-1percent",
    };
    Ok(json_with_etag(&headers, &dto))
}

// --- SSE subscribe ---
async fn v1_subscribe(State(st): State<AppState>) -> Sse<impl futures::Stream<Item = Result<SseEvent, axum::Error>>> {
    let rx = st.evt_tx.subscribe();
    let stream = BroadcastStream::new(rx).map(|res| match res {
        Ok(s) => Ok(SseEvent::default().data(s)),
        Err(_) => Err(axum::Error::new(std::io::Error::new(std::io::ErrorKind::Other, "broadcast closed"))),
    });
    Sse::new(stream)
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
    let f_ms = m.fetch_ms_total.load(Ordering::Relaxed);
    let f_cnt = m.fetch_count.load(Ordering::Relaxed);
    let f_avg = if f_cnt == 0 { 0 } else { f_ms / f_cnt };

    format!(
        "# HELP obex_node_up 1\n# TYPE obex_node_up gauge\nobex_node_up 1\n\
         # HELP headers_validated_total count\n# TYPE headers_validated_total counter\nheaders_validated_total {}\n\
         # HELP headers_rejected_total count\n# TYPE headers_rejected_total counter\nheaders_rejected_total {}\n\
         # HELP header_validate_avg_ms average\n# TYPE header_validate_avg_ms gauge\nheader_validate_avg_ms {}\n\
         # HELP alpha_i_verify_avg_ms average\n# TYPE alpha_i_verify_avg_ms gauge\nalpha_i_verify_avg_ms {}\n\
         # HELP root_build_avg_ms average\n# TYPE root_build_avg_ms gauge\nroot_build_avg_ms {}\n\
         # HELP fetch_success_total count\n# TYPE fetch_success_total counter\nfetch_success_total {}\n\
         # HELP fetch_fail_total count\n# TYPE fetch_fail_total counter\nfetch_fail_total {}\n\
         # HELP fetch_avg_ms average\n# TYPE fetch_avg_ms gauge\nfetch_avg_ms {}\n",
        hv, hr, hv_avg, ai_avg, rb_avg, fsucc, ffail, f_avg
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

// GET /alpha_i_index/{slot} — return concatenated 32-byte pks with local partrecs for slot
async fn get_alpha_i_index(
    Path(slot): Path<u64>,
    State(st): State<AppState>,
) -> Result<Response, (StatusCode, String)> {
    let map = st.partrecs.read().await;
    let mut out: Vec<u8> = Vec::new();
    for ((s, pk), _bytes) in map.iter() {
        if *s == slot {
            out.extend_from_slice(pk);
        }
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
    // Emit SSE per admitted ticket
    for leaf in leaves {
        if leaf.len() == 216 {
            let txid = hex::encode(&leaf[64..96]);
            let _ = st
                .evt_tx
                .send(serde_json::json!({"type":"ticketAdmitted","slot": slot, "txid": format!("0x{}", txid)}).to_string());
        }
    }
    Ok("ok".to_owned())
}

fn router(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/v1/info", get(v1_info))
        .route("/v1/head", get(v1_head))
        .route("/v1/headers", get(v1_headers_range))
        .route("/v1/slot/:slot", get(v1_slot_summary))
        .route("/v1/alpha_iii/:slot", get(v1_alpha_iii_json))
        .route("/v1/alpha_i_index/:slot", get(v1_alpha_i_index_json))
        .route("/v1/proof/ticket/:slot/:txid", get(v1_proof_ticket))
        .route("/v1/proof/participant/:slot/:pk", get(v1_proof_participant))
        .route("/v1/search", get(v1_search))
        .route("/v1/stats/supply", get(v1_stats_supply))
        .route("/v1/stats/participation", get(v1_stats_participation))
        .route("/v1/stats/fees", get(v1_stats_fees))
        .route("/v1/fees", get(v1_fees))
        .route("/v1/subscribe", get(v1_subscribe))
        .route("/v1/ticket/:txid", get(v1_ticket_by_txid))
        .route("/v1/peers", get(v1_peers))
        .route("/v1/account/:pk", get(v1_account))
        .route("/v1/tx/:txid", get(v1_tx_status))
        .route("/v1/tx", post(v1_tx_submit));
    Router::new()
        .route(
            "/alpha_i/:slot/:pk",
            get(get_alpha_i_partrec).post(post_alpha_i_partrec),
        )
        .route(
            "/alpha_i_index/:slot",
            get(get_alpha_i_index),
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
        .nest("/", v1)
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        )
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
    #[arg(long, default_value_t = 2)]
    per_peer_limit: usize,
    #[arg(long, default_value_t = 500)]
    backoff_base_ms: u64,
    #[arg(long, default_value_t = 8000)]
    backoff_max_ms: u64,
    #[arg(long, default_value_t = 5)]
    ban_threshold: u32,
    #[arg(long, default_value_t = 30000)]
    ban_duration_ms: u64,
    #[arg(long, default_value = "obex-alpha-testnet")]
    network_id: String,
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
        per_peer_limit: args.per_peer_limit,
        backoff_base_ms: args.backoff_base_ms,
        backoff_max_ms: args.backoff_max_ms,
        ban_threshold: args.ban_threshold,
        ban_duration_ms: args.ban_duration_ms,
        peer_state: Arc::new(RwLock::new(HashMap::new())),
        peer_limits: Arc::new(RwLock::new(HashMap::new())),
        reject_counts: Arc::new(RwLock::new(HashMap::new())),
        network_id: args.network_id.clone(),
        evt_tx: broadcast::channel(1024).0,
        tx_index: Arc::new(RwLock::new(HashMap::new())),
        spendable: Arc::new(RwLock::new(HashMap::new())),
        reserved: Arc::new(RwLock::new(HashMap::new())),
        next_nonce: Arc::new(RwLock::new(HashMap::new())),
        tx_status: Arc::new(RwLock::new(HashMap::new())),
    };
    // Initialize per-peer semaphores/state
    {
        let mut limits = state.peer_limits.write().await;
        let mut ps = state.peer_state.write().await;
        for p in state.peers.iter() {
            limits.entry(p.clone()).or_insert_with(|| Arc::new(Semaphore::new(state.per_peer_limit)));
            ps.entry(p.clone()).or_default();
        }
    }
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

fn ticket_root_from_db(db: &Db, slot: u64) -> Option<Hash256> {
    let mut key = Vec::with_capacity(8 + 5);
    key.extend_from_slice(&u64::to_le_bytes(slot));
    key.extend_from_slice(b"tixls");
    if let Ok(Some(ivec)) = db.get(key) {
        let buf = ivec.to_vec();
        const LEAF_LEN: usize = 216;
        if buf.len() % LEAF_LEN != 0 { return None; }
        let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(buf.len() / LEAF_LEN);
        let mut i = 0usize;
        while i < buf.len() {
            leaves.push(buf[i..i+LEAF_LEN].to_vec());
            i += LEAF_LEN;
        }
        return Some(merkle_root(&leaves));
    }
    None
}

fn part_root_from_db(db: &Db, slot: u64) -> Option<Hash256> {
    // Keys: slot(8) || pk(32) || "part"
    let prefix = u64::to_le_bytes(slot);
    let mut pks: Vec<[u8;32]> = Vec::new();
    for item in db.scan_prefix(prefix) {
        if let Ok((k, v)) = item {
            if k.len() == 8 + 32 + 4 && &k[8+32..] == b"part" {
                let mut pk = [0u8;32];
                pk.copy_from_slice(&k[8..8+32]);
                // Optional: verify decode to ensure it's canonical bytes
                if obex_alpha_i::decode_partrec(&v).is_ok() {
                    pks.push(pk);
                }
            }
        }
    }
    if pks.is_empty() { return None; }
    pks.sort_unstable();
    pks.dedup();
    let leaves: Vec<Vec<u8>> = pks.iter().map(|pk| {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&h_tag(constants::TAG_PART_LEAF, &[]));
        b.extend_from_slice(pk);
        b
    }).collect();
    Some(merkle_root(&leaves))
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
        {
            let mut rc = st.reject_counts.write().await;
            let k = match e {
                ValidateErr::BadParentLink => "BadParentLink",
                ValidateErr::BadSlot => "BadSlot",
                ValidateErr::VersionMismatch => "VersionMismatch",
                ValidateErr::VdfPiTooBig => "VdfPiTooBig",
                ValidateErr::VdfEllTooBig => "VdfEllTooBig",
                ValidateErr::BadSeedCommit => "BadSeedCommit",
                ValidateErr::BeaconInvalid => "BeaconInvalid",
                ValidateErr::TicketRootMismatch => "TicketRootMismatch",
                ValidateErr::PartRootMismatch => "PartRootMismatch",
                ValidateErr::TxRootPrevMismatch => "TxRootPrevMismatch",
            };
            *rc.entry(k).or_insert(0) += 1;
        }
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
    // Emit SSE event for new head
    let _ = st
        .evt_tx
        .send(serde_json::json!({"type":"newHead","slot": dto.slot}).to_string());

    // Header-first pull: if roots are non-empty, fetch bodies to verify locally.
    let need_part = !bool::from(dto.part_root.ct_eq(&h_tag(constants::TAG_MERKLE_EMPTY, &[])));
    let need_tix = !bool::from(dto.ticket_root.ct_eq(&h_tag(constants::TAG_MERKLE_EMPTY, &[])));
    if need_part || need_tix {
        let peers = st.peers.clone();
        let timeout = st.http_timeout_ms;
        let peer_limits = st.peer_limits.clone();
        let peer_state = st.peer_state.clone();
        let backoff_base = st.backoff_base_ms;
        let backoff_max = st.backoff_max_ms;
        let ban_thr = st.ban_threshold;
        let ban_dur = st.ban_duration_ms;
        let metrics = st.metrics.clone();
        let db = st.db.clone();
        let slot = dto.slot;
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(timeout))
                .build()
                .expect("client");
            for base in peers.iter() {
                let base = base.trim_end_matches('/');
                let mut ok = true;
                // Check ban/backoff
                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
                {
                    let ps_r = peer_state.read().await;
                    if let Some(ps) = ps_r.get(base) {
                        if now_ms < ps.banned_until_ms || now_ms < ps.next_allowed_ms {
                            continue;
                        }
                    }
                }
                // Acquire per-peer concurrency
                let sem_opt = {
                    let limits_r = peer_limits.read().await;
                    limits_r.get(base).cloned()
                };
                if let Some(sem) = sem_opt {
                    let _permit = sem.acquire_owned().await.ok();
                    if need_tix {
                        let url = format!("{}/alpha_iii/{}", base, slot);
                        let t0 = Instant::now();
                        match client.get(url).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.bytes().await {
                                    Ok(bytes_buf) => {
                                        log_json("info", 1100, "fetched_alpha_iii", serde_json::json!({"peer": base, "slot": slot, "len": bytes_buf.len()}));
                                        metrics.fetch_success_total.fetch_add(1, Ordering::Relaxed);
                                        let mut ps_w = peer_state.write().await;
                                        let s = ps_w.entry(base.to_string()).or_default();
                                        s.failures = 0;
                                        s.successes = s.successes.saturating_add(1);
                                        let dt_ms = t0.elapsed().as_millis() as u64;
                                        metrics.fetch_ms_total.fetch_add(dt_ms, Ordering::Relaxed);
                                        metrics.fetch_count.fetch_add(1, Ordering::Relaxed);
                                        // Persist leaves to DB and flush
                                        let mut key = Vec::with_capacity(8 + 5);
                                        key.extend_from_slice(&u64::to_le_bytes(slot));
                                        key.extend_from_slice(b"tixls");
                                        let _ = db.insert(key, &*bytes_buf);
                                        let _ = db.flush();
                                    }
                                    Err(e) => {
                                        ok = false;
                                        log_json("warn", 2101, "fetch_body_read_err", serde_json::json!({"peer": base, "slot": slot, "err": e.to_string()}));
                                        metrics.fetch_fail_total.fetch_add(1, Ordering::Relaxed);
                                        let dt_ms = t0.elapsed().as_millis() as u64;
                                        metrics.fetch_ms_total.fetch_add(dt_ms, Ordering::Relaxed);
                                        metrics.fetch_count.fetch_add(1, Ordering::Relaxed);
                                        // Optional: persistence deferred to POST handler; leave note
                                    }
                                }
                            }
                            Ok(resp) => {
                                ok = false;
                                log_json("warn", 2100, "fetch_body_http_err", serde_json::json!({"peer": base, "slot": slot, "status": resp.status().as_u16()}));
                                metrics.fetch_fail_total.fetch_add(1, Ordering::Relaxed);
                                let dt_ms = t0.elapsed().as_millis() as u64;
                                metrics.fetch_ms_total.fetch_add(dt_ms, Ordering::Relaxed);
                                metrics.fetch_count.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                ok = false;
                                log_json("warn", 2102, "fetch_body_net_err", serde_json::json!({"peer": base, "slot": slot, "err": e.to_string()}));
                                metrics.fetch_fail_total.fetch_add(1, Ordering::Relaxed);
                                let dt_ms = t0.elapsed().as_millis() as u64;
                                metrics.fetch_ms_total.fetch_add(dt_ms, Ordering::Relaxed);
                                metrics.fetch_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                // Backoff/ban on failure
                if !ok {
                    let mut ps_w = peer_state.write().await;
                    let s = ps_w.entry(base.to_string()).or_default();
                    s.failures = s.failures.saturating_add(1);
                    let pow = (s.failures.min(8) - 1) as u32;
                    let backoff = (backoff_base as u128) * (1u128 << pow);
                    let back_ms = backoff.min(backoff_max as u128);
                    s.next_allowed_ms = now_ms + back_ms;
                    if s.failures >= ban_thr as u64 {
                        s.banned_until_ms = now_ms + (ban_dur as u128);
                        log_json("warn", 2103, "peer_banned", serde_json::json!({"peer": base, "until_ms": s.banned_until_ms}));
                    }
                } else {
                    // Clear backoff on success
                    let mut ps_w = peer_state.write().await;
                    let s = ps_w.entry(base.to_string()).or_default();
                    s.next_allowed_ms = 0;
                }
                sleep(Duration::from_millis(50)).await;
            }
        });
    }
    put_header_db(&st.db, &dto.clone().into_header())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // Recompute roots from DB if persisted and retry policy on mismatch (ticket_root, part_root)
    if need_tix {
        if let Some(root_db) = ticket_root_from_db(&st.db, dto.slot) {
            if !bool::from(root_db.ct_eq(&h_tag(constants::TAG_MERKLE_EMPTY, &[]))) && !bool::from(root_db.ct_eq(&dto.ticket_root)) {
                log_json("warn", 2200, "ticket_root_mismatch_db", serde_json::json!({"slot": dto.slot}));
            }
        }
    }
    if need_part {
        if let Some(root_db) = part_root_from_db(&st.db, dto.slot) {
            if !bool::from(root_db.ct_eq(&h_tag(constants::TAG_MERKLE_EMPTY, &[]))) && !bool::from(root_db.ct_eq(&dto.part_root)) {
                log_json("warn", 2201, "part_root_mismatch_db", serde_json::json!({"slot": dto.slot}));
            }
        }
    }
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
    let mut txt = metrics_text(&st.metrics);
    let rc = st.reject_counts.read().await;
    for (k, v) in rc.iter() {
        txt.push_str(&format!("# HELP header_reject_{}_total count\n# TYPE header_reject_{}_total counter\nheader_reject_{}_total {}\n", k, k, k, v));
    }
    txt
}

async fn healthz(State(st): State<AppState>) -> Result<String, (StatusCode, String)> {
    let has_genesis = { st.headers.read().await.contains_key(&0) };
    if !has_genesis {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "missing genesis".to_owned()));
    }
    Ok("ok".to_owned())
}
