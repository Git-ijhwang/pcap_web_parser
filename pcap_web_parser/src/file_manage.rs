use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

static FILE_ID_GEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(u64);

impl FileId {
    pub fn new() -> Self {
        FileId(FILE_ID_GEN.fetch_add(1, Ordering::Relaxed))
    }
}


#[derive(Debug)]
pub struct FileContext {
    packets: Vec<Packet>,
    parsed_at: Instant,
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

    pub fn insert_file(&self, packets: Vec<Packet>) -> FileId {
        let file_id = FileId::new();

        let ctx = FileContext {
            packets,
            parsed_at: Instant::now(),
        };

        self.files.write().unwrap().insert(file_id, ctx);

        file_id
    }

    pub fn get_packet ( &self, file_id: FileId, packet_id: usize)
    -> Option<&Packet> {
        let files = self.files.read().unwrap();
        files.get(&file_id)?.packets.get(packet_id)
    }
}