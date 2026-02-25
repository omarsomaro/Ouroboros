//! Local storage for EtherSync messages
//! Supports both in-memory (default) and SQLite persistent storage

use crate::{message::EtherMessage, EtherSyncError};
use std::collections::HashMap;

/// Backend storage implementation
#[derive(Debug)]
enum StorageBackend {
    /// In-memory HashMap storage (default, for testing)
    Memory {
        messages: HashMap<(u64, [u8; 32]), Vec<EtherMessage>>,
    },
    /// SQLite persistent storage (requires "persistent-storage" feature)
    #[cfg(feature = "persistent-storage")]
    Sqlite { conn: rusqlite::Connection },
}

/// Local message storage with pluggable backend
#[derive(Debug)]
pub struct EtherStorage {
    backend: StorageBackend,
}

impl EtherStorage {
    /// Create new in-memory storage (default)
    pub fn new() -> Self {
        Self {
            backend: StorageBackend::Memory {
                messages: HashMap::new(),
            },
        }
    }

    /// Create new SQLite-backed storage
    ///
    /// # Arguments
    /// * `db_path` - Path to SQLite database file (":memory:" for in-memory SQLite)
    ///
    /// # Errors
    /// Returns error if database cannot be opened or initialized
    #[cfg(feature = "persistent-storage")]
    pub fn new_persistent(db_path: &str) -> Result<Self, EtherSyncError> {
        let conn = rusqlite::Connection::open(db_path).map_err(|e| {
            EtherSyncError::StorageError(format!("Failed to open SQLite database: {}", e))
        })?;

        // Initialize schema
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                slot INTEGER NOT NULL,
                hash BLOB NOT NULL,
                message BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                PRIMARY KEY (slot, hash, message)
            )",
            [],
        )
        .map_err(|e| EtherSyncError::StorageError(format!("Failed to create table: {}", e)))?;

        // Create index for slot queries
        conn.execute("CREATE INDEX IF NOT EXISTS idx_slot ON messages(slot)", [])
            .map_err(|e| EtherSyncError::StorageError(format!("Failed to create index: {}", e)))?;

        // Create index for timestamp (for cleanup)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)",
            [],
        )
        .map_err(|e| EtherSyncError::StorageError(format!("Failed to create index: {}", e)))?;

        Ok(Self {
            backend: StorageBackend::Sqlite { conn },
        })
    }

    /// Store a message
    pub fn store(
        &mut self,
        slot: u64,
        hash: [u8; 32],
        message: EtherMessage,
    ) -> Result<(), EtherSyncError> {
        match &mut self.backend {
            StorageBackend::Memory { messages } => {
                messages.entry((slot, hash)).or_default().push(message);
                Ok(())
            }
            #[cfg(feature = "persistent-storage")]
            StorageBackend::Sqlite { conn } => {
                let message_bytes = message.to_bytes();
                let timestamp = chrono::Utc::now().timestamp() as i64;

                conn.execute(
                    "INSERT OR REPLACE INTO messages (slot, hash, message, timestamp) 
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![slot as i64, &hash[..], message_bytes, timestamp],
                )
                .map_err(|e| {
                    EtherSyncError::StorageError(format!("Failed to store message: {}", e))
                })?;

                Ok(())
            }
        }
    }

    /// Get messages by slot and hash
    pub fn get(&self, slot: u64, hash: [u8; 32]) -> Result<Vec<EtherMessage>, EtherSyncError> {
        match &self.backend {
            StorageBackend::Memory { messages } => {
                Ok(messages.get(&(slot, hash)).cloned().unwrap_or_default())
            }
            #[cfg(feature = "persistent-storage")]
            StorageBackend::Sqlite { conn } => {
                let mut stmt = conn
                    .prepare("SELECT message FROM messages WHERE slot = ?1 AND hash = ?2")
                    .map_err(|e| {
                        EtherSyncError::StorageError(format!("Failed to prepare query: {}", e))
                    })?;

                let rows = stmt
                    .query_map(rusqlite::params![slot as i64, &hash[..]], |row| {
                        let bytes: Vec<u8> = row.get(0)?;
                        Ok(bytes)
                    })
                    .map_err(|e| EtherSyncError::StorageError(format!("Failed to query: {}", e)))?;

                let mut messages = Vec::new();
                for row in rows {
                    let bytes = row.map_err(|e| {
                        EtherSyncError::StorageError(format!("Failed to read row: {}", e))
                    })?;
                    let msg = EtherMessage::from_bytes(&bytes).map_err(|_| {
                        EtherSyncError::StorageError("Failed to deserialize message".to_string())
                    })?;
                    messages.push(msg);
                }

                Ok(messages)
            }
        }
    }

    /// Get all messages for a given slot
    pub fn get_slot_messages(&self, slot: u64) -> Result<Vec<EtherMessage>, EtherSyncError> {
        match &self.backend {
            StorageBackend::Memory { messages } => {
                let msgs: Vec<EtherMessage> = messages
                    .iter()
                    .filter(|((s, _), _)| *s == slot)
                    .flat_map(|(_, msgs)| msgs.iter().cloned())
                    .collect();
                Ok(msgs)
            }
            #[cfg(feature = "persistent-storage")]
            StorageBackend::Sqlite { conn } => {
                let mut stmt = conn
                    .prepare("SELECT message FROM messages WHERE slot = ?1")
                    .map_err(|e| {
                        EtherSyncError::StorageError(format!("Failed to prepare query: {}", e))
                    })?;

                let rows = stmt
                    .query_map([slot as i64], |row| {
                        let bytes: Vec<u8> = row.get(0)?;
                        Ok(bytes)
                    })
                    .map_err(|e| EtherSyncError::StorageError(format!("Failed to query: {}", e)))?;

                let mut messages = Vec::new();
                for row in rows {
                    let bytes = row.map_err(|e| {
                        EtherSyncError::StorageError(format!("Failed to read row: {}", e))
                    })?;
                    let msg = EtherMessage::from_bytes(&bytes).map_err(|_| {
                        EtherSyncError::StorageError("Failed to deserialize message".to_string())
                    })?;
                    messages.push(msg);
                }

                Ok(messages)
            }
        }
    }

    /// Cleanup old messages (older than given timestamp)
    ///
    /// # Arguments
    /// * `before_timestamp` - Unix timestamp; messages older than this are deleted
    #[cfg(feature = "persistent-storage")]
    pub fn cleanup_before(&self, before_timestamp: i64) -> Result<usize, EtherSyncError> {
        match &self.backend {
            StorageBackend::Memory { .. } => {
                // In-memory cleanup not implemented (would need mutable access to messages)
                tracing::debug!("Cleanup not implemented for in-memory storage");
                Ok(0)
            }
            StorageBackend::Sqlite { conn } => {
                let deleted = conn
                    .execute(
                        "DELETE FROM messages WHERE timestamp < ?1",
                        [before_timestamp],
                    )
                    .map_err(|e| {
                        EtherSyncError::StorageError(format!("Failed to cleanup: {}", e))
                    })?;

                Ok(deleted)
            }
        }
    }

    /// Cleanup messages older than a given duration from now
    #[cfg(feature = "persistent-storage")]
    pub fn cleanup_older_than(&self, duration: chrono::Duration) -> Result<usize, EtherSyncError> {
        let cutoff = (chrono::Utc::now() - duration).timestamp();
        self.cleanup_before(cutoff)
    }

    /// Get message count (for debugging/monitoring)
    pub fn message_count(&self) -> Result<usize, EtherSyncError> {
        match &self.backend {
            StorageBackend::Memory { messages } => Ok(messages.len()),
            #[cfg(feature = "persistent-storage")]
            StorageBackend::Sqlite { conn } => {
                let count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
                    .map_err(|e| EtherSyncError::StorageError(format!("Failed to count: {}", e)))?;
                Ok(count as usize)
            }
        }
    }
}

impl Default for EtherStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_storage() {
        let mut storage = EtherStorage::new();

        // Create a valid message using new()
        let msg = EtherMessage::new("test-passphrase", 1, b"hello", 0, 1).unwrap();
        let hash = [1u8; 32];

        storage.store(1, hash, msg.clone()).unwrap();

        let retrieved = storage.get(1, hash).unwrap();
        assert_eq!(retrieved.len(), 1);

        let slot_msgs = storage.get_slot_messages(1).unwrap();
        assert_eq!(slot_msgs.len(), 1);
    }

    #[test]
    #[cfg(feature = "persistent-storage")]
    fn test_sqlite_storage() {
        let mut storage = EtherStorage::new_persistent(":memory:").unwrap();

        let msg = EtherMessage::new("test-passphrase", 1, b"hello", 0, 1).unwrap();
        let hash = [1u8; 32];

        storage.store(1, hash, msg.clone()).unwrap();

        let retrieved = storage.get(1, hash).unwrap();
        assert_eq!(retrieved.len(), 1);

        let slot_msgs = storage.get_slot_messages(1).unwrap();
        assert_eq!(slot_msgs.len(), 1);
    }

    #[test]
    #[cfg(feature = "persistent-storage")]
    fn test_sqlite_cleanup() {
        let mut storage = EtherStorage::new_persistent(":memory:").unwrap();

        let msg = EtherMessage::new("test-passphrase", 1, b"hello", 0, 1).unwrap();
        let hash = [1u8; 32];

        storage.store(1, hash, msg.clone()).unwrap();

        // Verify message is stored
        assert_eq!(storage.message_count().unwrap(), 1);

        // Cleanup with a far past timestamp should delete nothing (message is newer)
        let past = chrono::Utc::now().timestamp() - 3600; // 1 hour ago
        let deleted = storage.cleanup_before(past).unwrap();
        assert_eq!(
            deleted, 0,
            "Past cleanup should delete nothing (message is newer)"
        );
        assert_eq!(storage.message_count().unwrap(), 1);

        // Cleanup with a far future timestamp should delete the message
        let future = chrono::Utc::now().timestamp() + 3600; // 1 hour in future
        let deleted = storage.cleanup_before(future).unwrap();
        assert_eq!(deleted, 1, "Future cleanup should delete the message");
        assert_eq!(storage.message_count().unwrap(), 0);
    }
}
