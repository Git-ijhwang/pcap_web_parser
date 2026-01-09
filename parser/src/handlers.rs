use std:: path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::fs;
use uuid::Uuid;
use axum_extra::extract::multipart::Field;
use axum::{
    extract::Query,
    http::StatusCode,
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use std::time::{ Duration, Instant};

use crate::*;
use crate::parse_pcap::*;
use crate::types::{Cache, FileInfo, PacketQuery};
use crate::file_manage::*;

async fn upload_file(
    cache: &Cache,
    original_name: &str,// file_data: &[u8]
    field: Field,
) -> Result<String, (StatusCode, String)>
{

    // UUID로 내부 파일 이름 생성
    let uuid = Uuid::new_v4().to_string();
    let tmp_filename = format!("web_parser-{}.pcap", uuid);
    let tmp_path = std::env::temp_dir().join(tmp_filename);

    // println!("[cache saved] {}", tmp_path.display());

    // 파일을 디스크에 쓴다 (비동기)
    if let Err(e) =
        save_field_to_file(field, &tmp_path).await {
            let msg = format!("Failed to save uploaded file: {}", e);
            let ret = (StatusCode::INTERNAL_SERVER_ERROR, msg);//.into_response();
            return Err(ret);
        }


    // 캐시에 등록
    let info = FileInfo {
        // uuid: uuid.clone(),
        path: tmp_path.clone(),
        original_name: original_name.to_string(),
        last_used: Instant::now(),
    };

    cache.write().await.insert(uuid.clone(), info);

    Ok(uuid) // 캐시 접근용 키 반환
}


/// Multipart field를 파일로 저장 (streaming)
async fn save_field_to_file(
    mut field: axum_extra::extract::multipart::Field,
    path: &PathBuf)
-> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut f = fs::File::create(path).await?;

    while let Some(chunk) = field.chunk().await? {
        f.write_all(&chunk).await?;
    }

    f.flush().await?;
    Ok(())
}

pub async fn handle_parse_summary(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart)
-> Response
{
    let cache = &state.cache;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {

        let name = field.name().map(|s| s.to_string()).unwrap_or_default();

        if name != "pcap" {
            continue;
        }

        // 원래 파일명(클라이언트가 제공한)
        let orig_filename = field.file_name().map(|s| s.to_string());
        let name = orig_filename.unwrap();

        /* 캐쉬에 등록 */
        let result = upload_file( &cache, &name, field,);

        let uuid = match result.await {
            Ok(uuid) => uuid,
            Err((code, msg)) => {
                return (code, msg).into_response();
            }
        };

        // 임시 파일 경로 생성
        let cache_read = cache.read().await; // std::sync::RwLock

        let tmp_path = // let cache_read = cache.read().await;
            cache_read
                .get(&uuid)
                .map(|info| info.path.clone())
                .unwrap_or_else(|| std::env::temp_dir().join(&uuid));


        // 파서는 보통 sync(블로킹)이므로 spawn_blocking 사용
        let tmp_path_clone = tmp_path.clone();

        let parse_result =
            // tokio::task::spawn_blocking(move || parse_file(&tmp_path_clone)).await;
            tokio::spawn(async move {
                simple_parse_pcap(&tmp_path_clone).await
            }).await;

        // parse 결과 처리
        match parse_result {
            Ok(Ok(parsed)) => {
                // let _ = tokio::fs::remove_file(&tmp_path).await;
                // let msg = Json(parsed);
                let file_id = state.pcaps.insert_file(uuid, tmp_path.clone(),
                    parsed.clone().packets);

                let resp = serde_json::json!({
                    "file_id": file_id.0,
                    "packets": parsed,
                });

                return (StatusCode::OK, Json(resp)).into_response();
                // return (StatusCode::OK, Json(parsed)).into_response();
            }
            Ok(Err(e)) => {
                // let _ = tokio::fs::remove_file(&tmp_path).await;
                let msg = format!("Parser error: {}", e);
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
            Err(join_err) => {
                // let _ = tokio::fs::remove_file(&tmp_path).await;
                let msg = format!("Internal error: {}", join_err);
                return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response();
            }
        }
    }

    return (StatusCode::BAD_REQUEST, "No 'pcap' file field found").into_response();
}



pub async fn handle_single_packet (
    State(state): State<Arc<AppState>>,
    Query(params): Query<PacketQuery> )
 -> Response
{
    let file_id = FileId(params.file_id);
    let packet_id = params.id;

    let pcaps = &state.pcaps;

    let (uuid, file_name) = match pcaps.get_file_name(file_id){
        Some(pkt) => (pkt.uuid, pkt.original_name),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "packet no found",
            ).into_response();
        }
    };

    let cache = &state.cache;

    let parse_result =
        tokio::spawn(async move {
            //5. parsing하기
            parse_single_packet(&file_name, packet_id).await
        }).await;

    if let Some(info) = cache.write().await.get_mut(&uuid) {
        info.last_used = Instant::now();
    }

    match parse_result {
        Ok(Ok(parsed)) => {
            let msg = Json(parsed);
            return (StatusCode::OK, msg).into_response()
        }

        Ok(Err(e)) => {
            let msg = format!("Parser error: {}", e);
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }

        Err(join_err) => {
            let msg = format!("Internal error: {}", join_err);
            return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response();
        }
    }
}


pub async fn
cleanup_cache(cache: &Cache, ttl: Duration)
{
    let mut cache_guard = cache.write().await;
    let now = Instant::now();

    // 삭제 대상 UUID 추출
    let expired: Vec<String> = cache_guard.iter()
        .filter(|(_, info)| now.duration_since(info.last_used) > ttl)
        .map(|(uuid, _)| uuid.clone())
        .collect();

    for uuid in expired {
        if let Some(info) = cache_guard.remove(&uuid) {
            // println!("Remove file");
            let _ = fs::remove_file(&info.path).await;
        }
    }
}


pub async fn
handle_callflow(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CallflowRequest>)
-> Response
{
    let file_id = FileId(req.file_id);
    let packet_id = req.packet_id;
    // let packet_summary = state.pcaps;

    // let cache = &state.cache;
    let pcaps = &state.pcaps;

    let (_, file_name) = match pcaps.get_file_name(file_id){
        Some(pkt) => (pkt.uuid, pkt.original_name),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "packet no found",
            ).into_response();
        }
    };

    let flow_result =
        tokio::spawn(async move {
            make_call_flow(&file_name, packet_id).await
        }).await;

    match flow_result {
        Ok(Ok(call_flow)) => {
            let msg = Json(call_flow);
            return (StatusCode::OK, msg).into_response()
        }

        Ok(Err(e)) => {
            let msg = format!("Call Flow error: {}", e);
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }

        Err(join_err) => {
            let msg = format!("Internal error: {}", join_err);
            return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response();
        }
    }

}


pub async fn
handle_cleanup(
    State(state): State<Arc<AppState>>)
    // State(cache): State<Cache>)
-> (StatusCode, String)
{
    let ttl = Duration::from_secs(60 * 5);
    let cache = &state.cache;
    let mut write = cache.write().await;
    let now = Instant::now();
    let mut removed_count = 0;

    // HashMap<String, CacheInfo>
    let keys: Vec<String> = write.keys().cloned().collect();

    for key in keys {
        if let Some(info) = write.get(&key) {
            if now.duration_since(info.last_used) > ttl {
                let _ = fs::remove_file(&info.path).await;

                write.remove(&key);

                removed_count += 1;
            }
        }
    }

    (
        StatusCode::OK,
        format!("cleanup done: {} files removed", removed_count)
    )
}