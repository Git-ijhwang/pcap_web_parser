use std:: path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::types::*;

static FILE_ID_GEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u64);

impl FileId {
    pub fn new() -> Self {
        FileId(FILE_ID_GEN.fetch_add(1, Ordering::Relaxed))
    }
}


#[derive(Debug, Clone)]
pub struct FileContext {
    pub uuid: String,
    pub original_name: PathBuf,
    pub packets: Vec<PacketSummary>,
    pub parsed_at: Instant,
}


#[derive(Debug)]
pub struct PcapFiles {
    pub files: RwLock<HashMap<FileId, FileContext>>,
}

impl PcapFiles {
    pub fn new() -> Self {
        PcapFiles {
            files: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert_file(&self, uuid:String, original_name:PathBuf, packets: Vec<PacketSummary>) -> FileId {
        let file_id = FileId::new();

        let ctx = FileContext {
            uuid,
            original_name,
            packets,
            parsed_at: Instant::now(),
        };

        self.files.write().unwrap().insert(file_id, ctx);

        file_id
    }

    pub fn get_file_name ( &self, file_id: FileId)
    // -> Option<PathBuf>
    -> Option<FileContext>
    {
        let files = self.files.read().unwrap();

        let result = files.get(&file_id).cloned();
        result 
    }

    pub fn get_packet ( &self, file_id: FileId, packet_id: usize)
    -> Option<Vec<PacketSummary>>
    {
        // 1. RwLock 읽기 잠금 획득
        let files = self.files.read().ok()?;

        // 2. HashMap에서 file_id에 해당하는 FileContext 검색
        let file_context = files.get(&file_id)?;

        // 3. packets 벡터에서 packet_id(인덱스)에 해당하는 패킷 검색
        // get()은 인덱스 범위를 벗어나면 None을 반환하므로 안전합니다.
        let packet = file_context.packets.get(packet_id)?;

        // 4. 결과 반환 (반환 타입이 Option<Vec<PacketSummary>>이므로 해당 패킷을 Vec에 담아 반환)
        // PacketSummary가 Clone을 구현하고 있어야 합니다.
        Some(vec![packet.clone()])
    }
}