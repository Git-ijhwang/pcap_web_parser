use std::{fs, collections::HashMap, };
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::fs::{File};
use uuid::Uuid;
use axum_extra::extract::multipart::Field;
use axum::{
    extract::Query,
    http::StatusCode,
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::*;
use crate::types::{Cache, FileInfo, PacketQuery};
use crate::parse_pcap::*;

async fn upload_file(
    cache: &Cache,
    original_name: &str,// file_data: &[u8]
    mut field: Field,
) -> Result<String, (StatusCode, String)>
{

    // UUID로 내부 파일 이름 생성
    let uuid = Uuid::new_v4().to_string();
    let tmp_filename = format!("upload-{}.pcap", uuid);
    let tmp_path = std::env::temp_dir().join(tmp_filename);

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

pub async fn handle_parse_summary(
    State(cache): State<Cache>,
    mut multipart: Multipart,
) -> Response
{
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


                // println!("==>{:?}", tmp_path.clone());
        // 파서는 보통 sync(블로킹)이므로 spawn_blocking 사용
        let detail = false;
        let tmp_path_clone = tmp_path.clone();
        let parse_result =
                // tokio::task::spawn_blocking(move || parse_file(&tmp_path_clone)).await;
                tokio::spawn(async move {
                    parse_pcap_summary(&tmp_path_clone, detail).await
                }).await;


        // parse 결과 처리
        match parse_result {
            Ok(Ok(parsed)) => {
                // let _ = tokio::fs::remove_file(&tmp_path).await;
                // let msg = Json(parsed);
                return (StatusCode::OK, Json(parsed)).into_response();
            }
            Ok(Err(e)) => {
                // let _ = tokio::fs::remove_file(&tmp_path).await;
                let msg = format!("Parser error: {}", e);
                println!("Bad Request!!!");
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

pub async fn handle_packet_detail (
    State(cache): State<Cache>,
    Query(params): Query<PacketQuery> )
// ) -> (StatusCode, Json<serde_json::Value>)
 -> Response
{
let filename = std::path::Path::new(&params.file)
    .file_name()
    .and_then(|os| os.to_str())
    .unwrap_or("");

let key = filename
    .trim_start_matches("upload-")
    .trim_end_matches(".pcap");

    //1. cache로부터 파일이름을 가져오기.
    let cache_read = cache.read().await;
    println!("cache로부터 파일 이름 가져오기.{}", params.file);
    println!("cache keys: {:?}", cache_read.keys());
    // let info = match cache_read.get(&params.file) {
    let info = match cache_read.get(key) {
        Some(v) => v.clone(),
        None => {
            let msg = format!("File not found in cache.");
            return (StatusCode::NOT_FOUND, msg).into_response();
        }
    };
    drop(cache_read);

    //2. 파일 읽기
    println!("파일 읽기");
    let data = match tokio::fs::read(&info.path).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let msg = format!("Failed to read file: {}.", e);
            return (StatusCode::NOT_FOUND, msg).into_response();
        }
    };

    //3. PacketQuery로부터 ID가져오기
    println!(" PacketQuery로부터 ID가져오기");
    let packet_id = params.id;
    println!("ID: {}", packet_id);

    //4. 파일에서 ID가 동일한 packet 읽기.
    let parse_result =
        tokio::spawn(async move {
            parse_single_packet(&info.path, packet_id).await
        }).await;
    //5. parsing하기


    //6. 결과 return 하기
    println!("결과 return 하기");
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