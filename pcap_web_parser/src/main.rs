use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{post, get},
    Json, Router,
};
use tokio::io::AsyncWriteExt;
use axum_extra::extract::Multipart;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

mod handlers;
mod gtp;
mod parse_pcap;
mod ip;
mod l4;
mod types;

use types::Cache;
use std::{fs, collections::HashMap, };
use tokio::sync::RwLock;
use crate::handlers::*;


#[tokio::main]
async fn main()
{
    let upload_dir = std::env::temp_dir();
    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));
    let cors = CorsLayer::permissive();

    let app = Router::new()
        .route("/api/parse", post(handle_parse_summary))
        .route("/api/packet_detail", get(handle_packet_detail))
        .with_state(cache) //router에 의해 호출되는 모든 함수들에 전달되는 사용자 data.
        .layer(cors); 

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    
    println!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}


/*
// handler
async fn handle_packet_detail(
    Query(params): Query<HashMap<String, String>>,
    // State(state): State<Arc<AppState>>, // 필요시
) -> impl IntoResponse {
    if let Some(id_str) = params.get("id") {
        if let Ok(id) = id_str.parse::<usize>() {
            // TODO: 실제로는 parse_file()에서 생성한 요약데이터(메모리 또는 임시 저장소)에서 id로 찾기
            // 여기서는 예시로 파일에서 다시 파싱하거나 캐시에서 꺼내야 함
            // 예: let detail = lookup_detail_by_id(id).await;
            // return Json(detail).into_response();
            return (StatusCode::OK, Json(json!({"id": id, "detail": "TODO"}))).into_response();
        }
    }
    (StatusCode::BAD_REQUEST, "missing id").into_response()
}
*/