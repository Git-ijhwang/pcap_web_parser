use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::fs::File;
use uuid::Uuid;
use axum::{
    extract::Query,
    http::StatusCode,
    extract::State,
    response::IntoResponse,
    Json,
};
use tokio::sync::RwLock;


use axum_extra::extract::multipart::Field;
use std::{fs, 
            collections::HashMap,
};

#[derive(Clone)]
struct FileInfo {
    path: PathBuf,
    original_name: String,
}

type Cache = Arc<RwLock<HashMap<String, FileInfo>>>;


use crate::*;
use crate::parse_pcap::{parse_pcap_file};

async fn upload_file(
    cache: &Cache,
    original_name: &str,// file_data: &[u8]
    field: Field,
    State(state): State<Arc<AppState>>,
    // State(state)
// ) -> Result<String, impl IntoResponse>
) -> Result<String, (StatusCode, String)>
{

    // UUID로 내부 파일 이름 생성
    let uuid = Uuid::new_v4().to_string();
    let tmp_filename = format!("upload-{}.pcap", uuid);
    let tmp_path = state.upload_dir.join(tmp_filename);
    // let file_path = upload_dir.join(format!("{}.dat", uuid));

    // 파일 저장
        // fs::write(&file_path, file_data).expect("failed to write file");

    // 파일을 디스크에 쓴다 (비동기)
    if let Err(e) =
        save_field_to_file(field, &tmp_path).await {
            let msg = format!("Failed to save uploaded file: {}", e);
            let ret = (StatusCode::INTERNAL_SERVER_ERROR, msg);//.into_response();
            return Err(ret);
        }


    // 캐시에 등록
    let info = FileInfo {
        path: tmp_path.clone(),
        original_name: original_name.to_string(),
    };

    cache.write().await.insert(uuid.clone(), info);

    // println!("✅ Uploaded: {} → {:?}", original_name, file_path);
    println!( "✅ 캐시에 저장됨: uuid={} name={} path={:?}",
            uuid, original_name, tmp_path
    );

    Ok(uuid) // 캐시 접근용 키 반환
}

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

use axum::response::Response;
/// 업로드 핸들러
///
/// Expect multipart form with a file field named "pcap".
pub async fn handle_parse_summary(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response
{
    let cache: Cache = Arc::new(RwLock::new(HashMap::new()));

    // 찾을 필드명: "pcap"
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().map(|s| s.to_string()).unwrap_or_default();
        if name != "pcap" {
            // 다른 필드가 먼저 올 수 있으니 계속 루프
            continue;
        }

        // 원래 파일명(클라이언트가 제공한)
        let orig_filename = field.file_name().map(|s| s.to_string());
        let name = orig_filename.unwrap();

        let result =
            upload_file( &cache,
                // &orig_filename.unwrap(),
                &name,
                field, State(state.clone()));

        let uuid = match result.await {
            Ok(uuid) => uuid,
            // Err(e) => {return e;},
            Err((code, msg)) => {
                return (code, msg).into_response();
                }
        };

        // 임시 파일 경로 생성
        // let uid = Uuid::new_v4().to_string();
        //Universally Unique Identifier = 전 세계에서 거의 절대 중복되지 않는 랜덤 ID 생성기

        // let tmp_filename = format!("upload-{}.pcap", uid);
        // let tmp_path = state.upload_dir.join(tmp_filename);
        let cache_read = cache.read().await; // std::sync::RwLock

        let tmp_path = // let cache_read = cache.read().await;
            cache_read
                .get(&uuid)
                .map(|info| info.path.clone())
                .unwrap_or_else(|| state.upload_dir.join(&uuid));


        // 파서는 보통 sync(블로킹)이므로 spawn_blocking 사용
        let detail = false;
        let tmp_path_clone = tmp_path.clone();
        let parse_result =
                // tokio::task::spawn_blocking(move || parse_file(&tmp_path_clone)).await;
                tokio::spawn(async move { parse_pcap_file(&tmp_path_clone, detail).await}).await;


        // parse 결과 처리
        match parse_result {
            Ok(Ok(parsed)) => {
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

    return (StatusCode::BAD_REQUEST, "No 'pcap' file field found").into_response();
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