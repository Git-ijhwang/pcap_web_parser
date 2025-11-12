/*
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use axum::serve;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello Axum" }));
n.rs

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();

    serve(listener, app).await.unwrap();
}
*/

mod gtpv2_types;
mod ipv4;
mod ipv6;
mod l4;
mod port;
mod gtp;
mod parse_pcap;
use parse_pcap::{parse_file};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};

#[derive(Serialize)]
pub struct ParsedResult {
    pub total_packets: usize,
    pub packets: Vec<PacketSummary>,
}

#[derive(Serialize)]
pub struct PacketSummary {
    pub id: usize,
    pub ts: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub description: String,
}

impl PacketSummary{
    pub fn new() -> Self {
        PacketSummary {
            id : 0,
            ts : String::new(),
            src_ip : String::new(),
            dst_ip : String::new(),
            src_port : 0,
            dst_port : 0,
            protocol : String::new(),
            length: 0,
            description: String::new(),
        }
    }
    
}

pub struct IpInfo {

    pub src_port: u16,
    pub dst_port: u16,
}
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
}
pub struct TcpInfo {
    pub seq: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

pub struct GtpInfo {
    pub msgtype: String,
    pub teid: u32,
}
pub struct PacketDetail {
    pub id: usize,
    pub ip: IpInfo,
    pub udp: Option<UdpInfo>,
    pub tcp: Option<TcpInfo>,
    pub gtp: Option<GtpInfo>,

}

use axum_extra::extract::Multipart;
use serde::Serialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use tower_http::cors::CorsLayer;

// 가정: parser 크레이트에서 아래를 export 하고 있음
// use pcap_parser::{parse_file, ParsedPcap};;


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
        .route("/api/parse", post(handle_parse))
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


/// 업로드 핸들러
///
/// Expect multipart form with a file field named "pcap".
async fn handle_parse(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse
{
    // 찾을 필드명: "pcap"
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        if name != "pcap" {
            // 다른 필드가 먼저 올 수 있으니 계속 루프
            continue;
        }

        // 원래 파일명(클라이언트가 제공한)
        let orig_filename = field.file_name().map(|s| s.to_string());

        // 임시 파일 경로 생성
        let uid = Uuid::new_v4().to_string();
        //Universally Unique Identifier = 전 세계에서 거의 절대 중복되지 않는 랜덤 ID 생성기

        let tmp_filename = format!("upload-{}.pcap", uid);
        let tmp_path = state.upload_dir.join(tmp_filename);

        // 파일을 디스크에 쓴다 (비동기)
        if let Err(e) =
            save_field_to_file(field, &tmp_path).await {
                let msg = format!("Failed to save uploaded file: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response();
        }

        // 파서는 보통 sync(블로킹)이므로 spawn_blocking 사용
        let tmp_path_clone = tmp_path.clone();
        let parse_result =
                // tokio::task::spawn_blocking(move || parse_file(&tmp_path_clone)).await;
                tokio::spawn(async move { parse_file(&tmp_path_clone).await}).await;

        // parse 결과 처리
        match parse_result {
            Ok(Ok(parsed)) => {
                // 성공하면 임시 파일 삭제(선택) — 여기선 삭제
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return (StatusCode::OK, Json(parsed)).into_response();
            }
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                let msg = format!("Parser error: {}", e);
                println!("Bad Request!!!");
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
            Err(join_err) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                let msg = format!("Internal error: {}", join_err);
                return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response();
            }
        }
    }

    (StatusCode::BAD_REQUEST, "No 'pcap' file field found").into_response()
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

/// Multipart field를 파일로 저장 (streaming)
async fn save_field_to_file(mut field: axum_extra::extract::multipart::Field, path: &PathBuf)
-> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut f = File::create(path).await?;

    while let Some(chunk) = field.chunk().await? {
        f.write_all(&chunk).await?;
    }

    f.flush().await?;
    Ok(())
}