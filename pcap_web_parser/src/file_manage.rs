use std:: path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::types::*;

static FILE_ID_GEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u64);

impl FileId {
    pub fn new() -> Self {
        FileId(FILE_ID_GEN.fetch_add(1, Ordering::Relaxed))
    }
}


#[derive(Debug)]
pub struct FileContext {
    original_name: PathBuf,
    packets: Vec<PacketSummary>,
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

    pub fn insert_file(&self, original_name:PathBuf, packets: Vec<PacketSummary>) -> FileId {
        let file_id = FileId::new();

        let ctx = FileContext {
            original_name,
            packets,
            parsed_at: Instant::now(),
        };

        self.files.write().unwrap().insert(file_id, ctx);

        file_id
    }

    pub fn get_file_name ( &self, file_id: FileId)
    -> Option<PathBuf>
    {
        let files = self.files.read().unwrap();

        files.get(&file_id).map(|ctx| ctx.original_name.clone())
    }

    // pub fn get_packet ( &self, file_id: FileId, packet_id: usize)
    // -> Option<String>
    // {
    //     let files = self.files.read().unwrap();

    //     files.get(&file_id)?.original_name
    // }
}