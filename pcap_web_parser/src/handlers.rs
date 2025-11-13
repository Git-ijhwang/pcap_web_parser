use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::fs::File;
use uuid::Uuid;
use axum::{
    extract::Query,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::*;
use crate::parse_pcap::{parse_pcap_file};

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

/// 업로드 핸들러
///
/// Expect multipart form with a file field named "pcap".
pub async fn handle_parse_summary(
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
        let detail = false;
        let tmp_path_clone = tmp_path.clone();
        let parse_result =
                // tokio::task::spawn_blocking(move || parse_file(&tmp_path_clone)).await;
                tokio::spawn(async move { parse_pcap_file(&tmp_path_clone, detail).await}).await;


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

#[derive(serde::Deserialize)]
struct PacketQuery {
    id: usize, // 프론트엔드에서 보내는 id
}

/*
pub async  fn handle_packet_detail(Query(params): Query<PacketQuery>) -> (StatusCode, Json<serde_json::Value>)
{
    let packet_id = params.id;

}
*/