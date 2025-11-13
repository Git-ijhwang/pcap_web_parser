use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
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

use crate::handlers::*;


struct AppState {
    // 필요하면 설정 추가 (예: 업로드 디렉토리, 파일 크기 제한 등)
    upload_dir: PathBuf,
}


#[tokio::main]
async fn main() {
    // 업로드 저장 경로 (운영 환경에서는 명시적 설정/권한 확인)
    let upload_dir = std::env::temp_dir();
    // -> /tmp 에 임시로 저장할 경로를 지정함. (특정 디렉토리를 지정할 수 도 있음.)

    let state = Arc::new(AppState { upload_dir });
    // thread safe한 upload file접근

    // 간단한 퍼미시브 CORS(개발용)
    let cors = CorsLayer::permissive();
    // -> CorsLayer는 HTTP middleware임.
    // 운영 환경에서는 보안상 permissive()를 그대로 쓰면 안 되고,
    // 특정 도메인/메서드/헤더만 허용하는 제한적 CORS 정책을 설정
    // 즉, 개발용
    // 목적: 브라우저에서 다른 도메인(origin)에서 오는 요청을 허용(CORS: Cross-Origin Resource Sharing)

    let app = Router::new()
        .route("/api/parse", post(handle_parse_summary))
        // .route("/api/packet_detail", post(handle_packet_detail))
        .with_state(state)
        .layer(cors); //라우터 전체에 CORS 미들웨어 적용
// /api/parse 경로에 POST 요청이 들어오면 handle_parse 핸들러를 실행하도록 라우팅
         ///api/parse 경로에 POST 요청이 들어오면 handle_parse 핸들러를 실행하도록 라우팅

    // Axum 0.7 권장 방식: serve with TcpListener
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    
    println!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    //addr (127.0.0.1:3000)로 TCP 소켓을 생성하고 바인딩(bind)
    //HTTP는 TCP 위에서 동작하므로, Axum/Hyper 서버도 내부적으로 TcpListener를 사용

    axum::serve(listener, app).await.unwrap();
    // TcpListener에서 연결을 받고
    // 연결별로 HTTP 요청을 app 라우터에 전달
    // 라우터가 POST /api/parse 요청을 handle_parse로 연결하고,
    // 핸들러가 Multipart 파일 처리 + 파싱 + JSON 반환

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