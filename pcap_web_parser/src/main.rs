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

mod file_manage;
mod handlers;
mod gtp;
mod parse_pcap;
mod ip;
mod types;
mod l4;

use types::Cache;
use handlers::*;
use file_manage::*;

    pub struct AppState {
        pub cache: Cache,
        pub pcaps: Arc<PcapFiles>,
    }

#[tokio::main]
async fn main()
{
    // let upload_dir = std::env::temp_dir();
    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));
// pub type Cache = Arc<RwLock<HashMap<String, FileInfo>>>;
    let pcaps = Arc::new(PcapFiles::new());

    let cors = CorsLayer::permissive();


    let state = Arc::new(AppState {
        cache,
        pcaps,
    });

    // --- This thread For Clean-up the Cache File
    let cache_for_cleanup = cache.clone();
    tokio::spawn(async move {
        let ttl = Duration::from_secs(300);     // 5분 TTL
        loop {
            cleanup_cache(&cache_for_cleanup, ttl).await;
            tokio::time::sleep(Duration::from_secs(60)).await; // 1분 간격 실행
        }
    });



    let app = Router::new()
        .route("/api/parse",
                post(handle_parse_summary))
        .route("/api/packet_detail",
                get(handle_single_packet))
        .route("/api/cleanup",
                get(handle_cleanup))
        .with_state(state) //router에 의해 호출되는 모든 함수들에 전달되는 사용자 data.
        .layer(cors); 

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    
    println!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}