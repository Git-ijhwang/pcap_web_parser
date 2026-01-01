use std::{collections::HashMap };
use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    routing::{post, get},
};
use tokio::sync::RwLock;
use axum_extra::extract::Multipart;
use tower_http::cors::CorsLayer;
use std::time::Duration;
use serde::Deserialize;

mod file_manage;
mod handlers;
mod gtp;
mod parse_pcap;
mod ip;
mod types;
mod l4;
mod gtp_call_flow;
mod call_flow_test;

use gtp_call_flow::*;
use types::Cache;
use handlers::*;
use file_manage::*;

pub struct AppState {
    pub cache: Cache,
    pub pcaps: Arc<PcapFiles>,
}


#[derive(Deserialize)]
pub struct CallflowRequest {
    pub file_id: u64,
    pub packet_id: usize,
}

#[tokio::main]
async fn main()
{
    // let upload_dir = std::env::temp_dir();
    // pub type Cache = Arc<RwLock<HashMap<String, FileInfo>>>;

    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));
    let pcaps = Arc::new(PcapFiles::new());
    let cors = CorsLayer::permissive();

    let cache_for_cleanup = cache.clone();
    let state = Arc::new(AppState {
        cache,
        pcaps,
    });

    // --- This thread For Clean-up the Cache File
    tokio::spawn(async move {
        let ttl = Duration::from_secs(300);     // 5분 TTL
        loop {
            cleanup_cache(&cache_for_cleanup, ttl).await;
            tokio::time::sleep(Duration::from_secs(60)).await; // 1분 간격 실행
        }
    });

    let app = Router::new()
        .route("/api/parse", post(handle_parse_summary))
        .route("/api/packet_detail", get(handle_single_packet))
        .route("/api/cleanup", get(handle_cleanup))
        .route("/api/gtp/callflow", post( handle_callflow))
        .with_state(state) //router에 의해 호출되는 모든 함수들에 전달되는 사용자 data.
        .layer(cors); 

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    
    println!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}