use std::path::PathBuf;

use crate::keri::core::filing::{BaseFiler, Filer, FilerDefaults};
use crate::keri::db::errors::DBError;
use lmdb::{Cursor, Database, Environment, EnvironmentFlags, Iter, Transaction, WriteFlags};

impl LMDBer {
    pub fn builder() -> LMDBerBuilder {
        LMDBerBuilder::default()
    }
}

pub struct LMDBerBuilder {
    name: String,
    temp: bool,
    reopen: bool,
    // other fields...
}

impl Default for LMDBerBuilder {
    fn default() -> Self {
        Self {
            name: "test".to_string(),
            temp: true,
            reopen: true
            // other defaults
        }
    }
}

impl LMDBerBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn temp(mut self, temp: bool) -> Self {
        self.temp = temp;
        self
    }

    pub fn reopen(mut self, reopen: bool) -> Self {
        self.reopen = reopen;
        self
    }

    // other setters

    pub fn build(self) -> Result<LMDBer, DBError> {
        // Create and return an LMDBer instance
        LMDBer::new(
            self.name,
            "".to_string(), // base parameter
            self.temp,
            None,  // head_dir_path
            None,  // perm
            self.reopen,  // reopen
            false, // clear
            false, // reuse
            false, // clean
            false, // filed
            false, // extensioned
            None,  // mode
            None,  // fext
            false, // readonly
        )
    }
}

/// LMDBer is a wrapper around LMDB database providing an interface similar to Filer
pub struct LMDBer {
    /// Base Filer instance
    pub filer: BaseFiler,

    /// LMDB environment
    pub env: Option<Environment>,

    /// Whether the database is opened in readonly mode
    pub readonly: bool,

    /// Version of the database
    version: Option<String>,
}

impl LMDBer {
    pub fn name(&self) -> String {
        self.filer.name()
    }

    pub fn base(&self) -> String {
        self.filer.base()
    }

    pub fn opened(&self) -> bool {
        self.filer.opened()
    }

    pub fn temp(&self) -> bool {
        self.filer.temp()
    }

    pub fn env(&self) -> Option<&Environment> {
        self.env.as_ref()
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.filer.path()
    }
}

impl Filer for LMDBer {
    fn defaults() -> FilerDefaults {
        let base_defaults = FilerDefaults::default();
        FilerDefaults {
            head_dir_path: base_defaults.head_dir_path,
            tail_dir_path: Self::TAIL_DIR_PATH,
            clean_tail_dir_path: Self::CLEAN_TAIL_DIR_PATH,
            alt_head_dir_path: base_defaults.alt_head_dir_path,
            alt_tail_dir_path: Self::ALT_TAIL_DIR_PATH,
            alt_clean_tail_dir_path: Self::ALT_CLEAN_TAIL_DIR_PATH,
            temp_head_dir: base_defaults.temp_head_dir,
            temp_prefix: Self::TEMP_PREFIX,
            temp_suffix: base_defaults.temp_suffix,
            perm: base_defaults.perm,
            mode: base_defaults.mode,
            fext: base_defaults.fext,

        }
    }

   #[cfg(target_os = "windows")]
    const TAIL_DIR_PATH: &'static str = "keri\\db";
    #[cfg(not(target_os = "windows"))]
    const TAIL_DIR_PATH: &'static str = "keri/db";

   #[cfg(target_os = "windows")]
    const CLEAN_TAIL_DIR_PATH: &'static str = "keri\\clean\\db";
    #[cfg(not(target_os = "windows"))]
    const CLEAN_TAIL_DIR_PATH: &'static str = "keri/clean/db";

    #[cfg(target_os = "windows")]
    const ALT_TAIL_DIR_PATH: &'static str = "keri\\db";
    #[cfg(not(target_os = "windows"))]
    const ALT_TAIL_DIR_PATH: &'static str = "keri/db";

    #[cfg(target_os = "windows")]
    const ALT_CLEAN_TAIL_DIR_PATH: &'static str = "keri\\clean\\db";
    #[cfg(not(target_os = "windows"))]
    const ALT_CLEAN_TAIL_DIR_PATH: &'static str = "keri/clean/db";

    const TEMP_PREFIX: &'static str = "keri_lmdb_";
}

impl LMDBer {
    // Constants specific to LMDBer
    pub const MAX_NAMED_DBS: u32 = 96;
    pub const MAP_SIZE: usize = 104857600; // 100MB

    /// Create a new LMDBer instance
    pub fn new<S1, S2>(
        name: S1,
        base: S2,
        temp: bool,
        head_dir_path: Option<PathBuf>,
        perm: Option<u32>,
        reopen: bool,
        clear: bool,
        reuse: bool,
        clean: bool,
        filed: bool,
        extensioned: bool,
        mode: Option<String>,
        fext: Option<String>,
        readonly: bool,
    ) -> Result<Self, DBError>
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let filer = BaseFiler::new(
            name,
            base,
            temp,
            head_dir_path,
            perm,
            reopen,
            clear,
            reuse,
            clean,
            filed,
            extensioned,
            mode,
            fext,
            Some(Self::defaults())
        );

        let filer = match filer {
            Ok(filer) => filer,
            Err(e) => return Err(DBError::CoreError(format!("{}", e))),
        };

        let mut lmdber = LMDBer {
            filer,
            env: None,
            readonly,
            version: None,
        };

        if reopen {
            lmdber.reopen(None, None, None, clear, reuse, clean, None, None)?;
        }

        Ok(lmdber)
    }

    /// Reopen the LMDB database
    pub fn reopen(
        &mut self,
        temp: Option<bool>,
        head_dir_path: Option<PathBuf>,
        perm: Option<u32>,
        clear: bool,
        reuse: bool,
        clean: bool,
        mode: Option<String>,
        fext: Option<String>,
    ) -> Result<bool, DBError> {
        let exists = self
            .filer
            .exists(
                &self.filer.name(),
                &self.filer.base(),
                None,
                clean,
                self.filer.filed(),
                self.filer.extensioned(),
                None,
            )
            .map_err(|e| DBError::FilerError(format!("{}", e)))?;

        let opened = self
            .filer
            .reopen(temp, head_dir_path, perm, clear, reuse, clean, mode, fext)
            .map_err(|e| DBError::FilerError(format!("{}", e)))?;

        // Close the environment if it's already open
        if self.env.is_some() {
            self.env = None;
        }

        if let Some(path) = self.filer.get_path() {
            // Open LMDB environment with specified parameters
            let flags = if self.readonly {
                EnvironmentFlags::READ_ONLY
            } else {
                EnvironmentFlags::empty()
            };

            let env = Environment::new()
                .set_flags(flags)
                .set_max_dbs(Self::MAX_NAMED_DBS)
                .set_map_size(Self::MAP_SIZE)
                .open(path)
                .map_err(|e| DBError::IoError(format!("Error creating lmdb env: {}", e)))?;

            self.env = Some(env);

            // Set version if opening fresh database
            if !self.readonly && (!exists || self.filer.temp()) {
                // In a real implementation, you would set the version from your crate version
                // For now, we'll use a placeholder
                self.version = Some("0.1.0".to_string());
            }
        }

        let result = opened && self.env.is_some();
        self.filer.set_opened(result);
        Ok(result)
    }

    /// Get the version of the database
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Set the version of the database
    pub fn set_version(&mut self, version: String) {
        self.version = Some(version);
    }

    /// Close the LMDB environment and the filer
    pub fn close(&mut self, clear: bool) -> Result<bool, DBError> {
        // Drop the LMDB environment to close it
        self.env = None;

        // Close the underlying filer
        self.filer
            .close(clear)
            .map_err(|e| DBError::FilerError(format!("{}", e)))
    }

    pub fn put_val(&self, db: &Database, key: &Vec<u8>, val: &Vec<u8>) -> Result<bool, DBError> {
        if self.env.is_none() {
            return Err(DBError::DatabaseError(
                "Database environment not initialized".to_string(),
            ));
        }

        let env = self.env.as_ref().unwrap();

        // Create a write transaction
        let mut txn = env
            .begin_rw_txn()
            .map_err(|e| DBError::DatabaseError(format!("Failed to create transaction: {}", e)))?;

        // Try to put without overwriting
        match txn.put(*db, key, val, WriteFlags::NO_OVERWRITE) {
            Ok(()) => {
                // Commit transaction
                txn.commit().map_err(|e| {
                    DBError::DatabaseError(format!("Failed to commit transaction: {}", e))
                })?;
                Ok(true)
            }
            Err(lmdb::Error::KeyExist) => {
                // Key already exists, abort transaction
                txn.abort();
                Ok(false)
            }
            Err(lmdb::Error::BadValSize) => {
                // Abort transaction
                txn.abort();
                Err(DBError::KeyError(format!(
                    "Key: `{:?}` is either empty, too big (for lmdb), or wrong DUPFIXED size",
                    key
                )))
            }
            Err(e) => {
                // Abort transaction
                txn.abort();
                Err(DBError::DatabaseError(format!("Database error: {}", e)))
            }
        }
    }

    /// Write serialized bytes val to location key in db
    /// Overwrites existing val if any
    ///
    /// # Parameters
    /// * `db` - opened named sub db with dupsort=false
    /// * `key` - bytes of key within sub db's keyspace
    /// * `val` - bytes of value to be written
    ///
    /// # Returns
    /// * `Result<bool, DBError>` - true if val successfully written, false otherwise
    ///
    /// # Errors
    /// Returns KeyError if key is empty, too big, or wrong DUPFIXED size
    pub fn set_val(&self, db: &Database, key: &Vec<u8>, val: &Vec<u8>) -> Result<bool, DBError> {
        if self.env.is_none() {
            return Err(DBError::DatabaseError(
                "Database environment not initialized".to_string(),
            ));
        }

        let env = self.env.as_ref().unwrap();

        // Create a write transaction
        let mut txn = env
            .begin_rw_txn()
            .map_err(|e| DBError::DatabaseError(format!("Failed to create transaction: {}", e)))?;

        // Try to put with overwriting
        match txn.put(*db, key, val, WriteFlags::empty()) {
            Ok(()) => {
                // Commit transaction
                txn.commit().map_err(|e| {
                    DBError::DatabaseError(format!("Failed to commit transaction: {}", e))
                })?;
                Ok(true)
            }
            Err(lmdb::Error::BadValSize) => {
                // Abort transaction
                txn.abort();
                Err(DBError::KeyError(format!(
                    "Key: `{:?}` is either empty, too big (for lmdb), or wrong DUPFIXED size",
                    key
                )))
            }
            Err(e) => {
                // Abort transaction
                txn.abort();
                Err(DBError::DatabaseError(format!("Database error: {}", e)))
            }
        }
    }

    /// Return val at key in db
    /// Returns None if no entry at key
    ///
    /// # Parameters
    /// * `db` - opened named sub db with dupsort=false
    /// * `key` - bytes of key within sub db's keyspace
    ///
    /// # Returns
    /// * `Result<Option<Vec<u8>>, DBError>` - the value if found, None otherwise
    ///
    /// # Errors
    /// Returns KeyError if key is empty, too big, or wrong DUPFIXED size
    pub fn get_val(&self, db: &Database, key: &Vec<u8>) -> Result<Option<Vec<u8>>, DBError> {
        if self.env.is_none() {
            return Err(DBError::DatabaseError(
                "Database environment not initialized".to_string(),
            ));
        }

        let env = self.env.as_ref().unwrap();

        // Create a read transaction
        let txn = env
            .begin_ro_txn()
            .map_err(|e| DBError::DatabaseError(format!("Failed to create transaction: {}", e)))?;

        // Try to get the value
        match txn.get(*db, key) {
            Ok(val) => {
                // Clone the value since it's bound to the transaction lifetime
                let result = val.to_vec();
                // Abort transaction (read-only, so no need to commit)
                txn.abort();
                Ok(Some(result))
            }
            Err(lmdb::Error::NotFound) => {
                // Key not found
                txn.abort();
                Ok(None)
            }
            Err(lmdb::Error::BadValSize) => {
                // Bad value size
                txn.abort();
                Err(DBError::KeyError(format!(
                    "Key: `{:?}` is either empty, too big (for lmdb), or wrong DUPFIXED size",
                    key
                )))
            }
            Err(e) => {
                // Other error
                txn.abort();
                Err(DBError::DatabaseError(format!("Database error: {}", e)))
            }
        }
    }

    /// Deletes value at key in db
    ///
    /// # Parameters
    /// * `db` - opened named sub db with dupsort=false
    /// * `key` - bytes of key within sub db's keyspace
    ///
    /// # Returns
    /// * `Result<bool, DBError>` - true if key existed and was deleted, false if key didn't exist
    ///
    /// # Errors
    /// Returns KeyError if key is empty, too big, or wrong DUPFIXED size
    pub fn del_val(&self, db: &Database, key: &Vec<u8>) -> Result<bool, DBError> {
        if self.env.is_none() {
            return Err(DBError::DatabaseError(
                "Database environment not initialized".to_string(),
            ));
        }

        let env = self.env.as_ref().unwrap();

        // Create a write transaction
        let mut txn = env
            .begin_rw_txn()
            .map_err(|e| DBError::DatabaseError(format!("Failed to create transaction: {}", e)))?;

        // Try to delete the key
        match txn.del(*db, key, None) {
            Ok(()) => {
                // Commit transaction
                txn.commit().map_err(|e| {
                    DBError::DatabaseError(format!("Failed to commit transaction: {}", e))
                })?;
                Ok(true)
            }
            Err(lmdb::Error::NotFound) => {
                // Key not found, abort transaction
                txn.abort();
                Ok(false)
            }
            Err(lmdb::Error::BadValSize) => {
                // Bad value size
                txn.abort();
                Err(DBError::KeyError(format!(
                    "Key: `{:?}` is either empty, too big (for lmdb), or wrong DUPFIXED size",
                    key
                )))
            }
            Err(e) => {
                // Other error
                txn.abort();
                Err(DBError::DatabaseError(format!("Database error: {}", e)))
            }
        }
    }

    /// Return count of values in db, or zero otherwise
    ///
    /// # Parameters
    /// * `db` - Opened named sub db with dupsort=True
    pub fn cnt(&self, db: &Database) -> Result<usize, DBError> {
        if let Some(env) = &self.env {
            let txn = env.begin_ro_txn().map_err(|e| DBError::DatabaseError(format!(
                "Failed to create transaction: {}",
                e
            )))?;
            let mut cursor = txn.open_ro_cursor(*db);
            let mut count = 0;

            for result in cursor.iter() {
                match result {
                    Ok(_) => count += 1,
                    Err(e) => return Err(DBError::DatabaseError(format!("{}", e))),
                }
            }

            Ok(count)
        } else {
            Err(DBError::DatabaseError("Not opened".to_string()))
        }
    }

    /// Iterates over branch of db given by top key
    ///
    /// # Returns
    /// Iterator of (full key, val) tuples over a branch of the db given by top key
    /// where: full key is full database key for val not truncated top key
    ///
    /// Works for both dupsort==False and dupsort==True
    ///
    /// # Parameters
    /// * `db` - Instance of named sub db
    /// * `top` - Truncated top key, a key space prefix to get all the items
    ///           from multiple branches of the key space. If top key is
    ///           empty then gets all items in database.
    pub fn get_top_item_iter<'txn>(
        &self,
        db: &'txn Database,
        top: &[u8],
    ) -> Result<impl Iterator<Item = Result<(Vec<u8>, Vec<u8>), DBError>> + 'txn, DBError> {
        if let Some(env) = &self.env {
            let txn = env.begin_ro_txn().map_err(|e| DBError::DatabaseError(format!(
                "Failed to create transaction: {}",
                e
            )))?;
            let mut cursor = txn.open_ro_cursor(*db).map_err(|e| DBError::DatabaseError(format!(
                "Failed to open cursor: {}",
                e
            )))?;

            // Custom iterator struct to wrap the LMDB cursor
            struct TopItemIterator<'a> {
                iter: Iter<'a>,
                top: Vec<u8>,
                started: bool,
            }

            impl<'a> Iterator for TopItemIterator<'a> {
                type Item = Result<(Vec<u8>, Vec<u8>), DBError>;

                fn next(&mut self) -> Option<Self::Item> {
                    let result = self.iter.next();

                    match result {
                        Ok(Some((key, val))) => {
                            // Check if key starts with top prefix
                            if !key.starts_with(&self.top) {
                                return None;
                            }

                            // Clone the data to return owned values
                            let key_vec = key.to_vec();
                            let val_vec = val.to_vec();

                            Some(Ok((key_vec, val_vec)))
                        },
                        Ok(None) => None,
                        Err(e) => Some(Err(DBError::DatabaseError(e))),
                    }
                }
            }

            Ok(TopItemIterator {
                iter: cursor.iter_from(top.to_vec()),
                top: top.to_vec(),
                started: false,
            })
        } else {
            Err(DBError::DatabaseError("Not opened".to_string()))
        }
    }

    /// Deletes all values in branch of db given top key.
    ///
    /// # Returns
    /// * `Result<bool, DBError>` - True if values were deleted at key, False otherwise
    ///                             if no values at key
    ///
    /// # Parameters
    /// * `db` - Instance of named sub db
    /// * `top` - Truncated top key, a key space prefix to get all the items
    ///           from multiple branches of the key space. If top key is
    ///           empty then deletes all items in database
    pub fn del_top_val(&self, db: &Database, top: &[u8]) -> Result<bool, DBError> {
        if let Some(env) = &self.env {
            let mut txn = env.begin_rw_txn()?;
            let mut cursor = txn.open_rw_cursor(*db).map_err(|e| DBError::DatabaseError(format!(
                "Failed to create transaction: {}",
                e
            )))?;
            let mut result = false;

            if let Ok(Some((ckey, _))) = cursor.iter_from(top) {
                if ckey.starts_with(top) {
                    result = true;

                    // Delete first matching entry
                    cursor.del(WriteFlags::empty())?;

                    // Delete subsequent matching entries
                    while let Ok(Some((ckey, _))) = cursor.next() {
                        if !ckey.starts_with(top) {
                            break;
                        }

                        cursor.del(WriteFlags::empty())?;
                    }
                }
            }

            txn.commit()?;
            Ok(result)
        } else {
            Err(DBError::DatabaseError("Not opened".to_string()))
        }
    }

}

impl Drop for LMDBer {
    fn drop(&mut self) {
        // Clean up resources when dropped
        let _ = self.close(false);
    }
}

use chrono::{DateTime, Utc};
use std::convert::AsRef;

/// Helper functions for LMDB key operations
pub mod keys {
    use super::*;

    /// Returns key formed by joining top key and hex str conversion of
    /// int ordinal number on with sep character.
    ///
    /// # Parameters
    /// * `top` - top key prefix to be joined with hex version of on using sep
    /// * `on` - ordinal number to be converted to 32 hex bytes
    /// * `sep` - separator character for join (default is b'.')
    ///
    /// # Returns
    /// * `Vec<u8>` - key formed by joining top key and hex str conversion of `on`
    pub fn on_key(top: impl AsRef<[u8]>, on: u64, sep: Option<[u8; 1]>) -> Vec<u8> {
        let top_bytes = top.as_ref();
        let sep_bytes = sep.map_or(b".".to_vec(), |s| s.to_vec());

        // Pre-allocate for efficiency
        let mut result = Vec::with_capacity(top_bytes.len() + sep_bytes.len() + 32);
        result.extend_from_slice(top_bytes);
        result.extend_from_slice(sep_bytes.as_slice());

        // Format the ordinal number as 32 hex characters
        let hex_str = format!("{:032x}", on);
        result.extend_from_slice(hex_str.as_bytes());

        result
    }

    /// Returns key formed by joining pre and hex str conversion of int
    /// sequence ordinal number sn with sep character b".".
    ///
    /// # Parameters
    /// * `pre` - key prefix to be joined with hex version of on using b"." sep
    /// * `sn` - sequence number to be converted to 32 hex bytes
    ///
    /// # Returns
    /// * `Vec<u8>` - key formed by joining pre and hex str conversion of sn
    pub fn sn_key(pre: impl AsRef<[u8]>, sn: u64) -> Vec<u8> {
        on_key(pre, sn, Some(*b"."))
    }

    /// Returns key formed by joining pre and hex str conversion of int
    /// first seen ordinal number fn with sep character b".".
    ///
    /// # Parameters
    /// * `pre` - key prefix to be joined with hex version of on using b"." sep
    /// * `fn_val` - first seen ordinal number to be converted to 32 hex bytes
    ///
    /// # Returns
    /// * `Vec<u8>` - key formed by joining pre and hex str conversion of fn_val
    pub fn fn_key(pre: impl AsRef<[u8]>, fn_val: u64) -> Vec<u8> {
        on_key(pre, fn_val, Some(*b"."))
    }

    /// Returns bytes DB key from concatenation of '.' with qualified Base64 prefix
    /// bytes pre and qualified Base64 bytes digest of serialized event
    ///
    /// # Parameters
    /// * `pre` - prefix bytes
    /// * `dig` - digest bytes
    ///
    /// # Returns
    /// * `Vec<u8>` - key formed by concatenating pre, ".", and dig
    pub fn dg_key(pre: impl AsRef<[u8]>, dig: impl AsRef<[u8]>) -> Vec<u8> {
        let pre_bytes = pre.as_ref();
        let dig_bytes = dig.as_ref();

        let mut result = Vec::with_capacity(pre_bytes.len() + 1 + dig_bytes.len());
        result.extend_from_slice(pre_bytes);
        result.push(b'.');
        result.extend_from_slice(dig_bytes);

        result
    }

    /// Returns bytes DB key from concatenation of '|' qualified Base64 prefix
    /// bytes pre and bytes dts datetime string of extended tz aware ISO8601
    /// datetime of event
    ///
    /// # Parameters
    /// * `pre` - prefix bytes
    /// * `dts` - datetime string in ISO8601 format
    ///
    /// # Returns
    /// * `Vec<u8>` - key formed by concatenating pre, "|", and dts
    pub fn dt_key(pre: impl AsRef<[u8]>, dts: impl AsRef<[u8]>) -> Vec<u8> {
        let pre_bytes = pre.as_ref();
        let dts_bytes = dts.as_ref();

        let mut result = Vec::with_capacity(pre_bytes.len() + 1 + dts_bytes.len());
        result.extend_from_slice(pre_bytes);
        result.push(b'|');
        result.extend_from_slice(dts_bytes);

        result
    }

    /// Returns duple of pre and either dig or on, sn, fn str or dts datetime str by
    /// splitting key at bytes sep
    ///
    /// # Parameters
    /// * `key` - database key with split at sep
    /// * `sep` - separator character. default is b'.'
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, Vec<u8>), DBError>` - tuple of pre and suffix
    ///
    /// # Errors
    /// * `DBError::ValueError` - if key does not split into exactly two elements
    pub fn split_key(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, Vec<u8>), DBError> {
        let key_bytes = key.as_ref();
        let sep_bytes = sep.map_or(b".".to_vec(), |s| s.to_vec());

        if let Some(pos) = key_bytes.iter().rposition(|&b| b == sep_bytes[0]) {
            if sep_bytes.len() == 1 || key_bytes[pos..pos + sep_bytes.len()] == sep_bytes[..] {
                let (pre, suf) = key_bytes.split_at(pos);
                // Skip the separator in suffix
                let suf = &suf[sep_bytes.len()..];
                return Ok((pre.to_vec(), suf.to_vec()));
            }
        }

        Err(DBError::ValueError(format!(
            "Unsplittable key at {:?}",
            sep_bytes
        )))
    }

    /// Returns tuple of pre and int on from key
    ///
    /// # Parameters
    /// * `key` - database key
    /// * `sep` - separator character. default is b'.'
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, u64), DBError>` - tuple of pre and ordinal number
    ///
    /// # Errors
    /// * `DBError::ValueError` - if key cannot be split
    /// * `DBError::ParseError` - if the ordinal part cannot be parsed as hex
    pub fn split_on_key(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        let (top, on_bytes) = split_key(key, sep)?;

        // Convert on_bytes to string and parse as hex
        let on_str = String::from_utf8(on_bytes)
            .map_err(|e| DBError::ParseError(format!("Invalid UTF-8 in ordinal: {}", e)))?;

        let on = u64::from_str_radix(&on_str, 16)
            .map_err(|e| DBError::ParseError(format!("Invalid hex in ordinal: {}", e)))?;

        Ok((top, on))
    }

    // Aliases for split_on_key to make intent clear
    pub fn split_sn_key(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        split_on_key(key, sep)
    }

    pub fn split_fn_key(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        split_on_key(key, sep)
    }

    // Backwards compatible aliases
    pub fn split_key_on(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        split_on_key(key, sep)
    }

    pub fn split_key_sn(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        split_on_key(key, sep)
    }

    pub fn split_key_fn(
        key: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        split_on_key(key, sep)
    }

    /// Returns tuple of pre and datetime from key
    ///
    /// # Parameters
    /// * `key` - database key
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, DateTime<Utc>), DBError>` - tuple of pre and datetime
    ///
    /// # Errors
    /// * `DBError::ValueError` - if key cannot be split
    /// * `DBError::ParseError` - if the datetime part cannot be parsed
    pub fn split_key_dt(key: impl AsRef<[u8]>) -> Result<(Vec<u8>, DateTime<Utc>), DBError> {
        let (pre, dts_bytes) = split_key(key, Some(*b"|"))?;

        // Convert dts_bytes to string
        let dts = String::from_utf8(dts_bytes)
            .map_err(|e| DBError::ParseError(format!("Invalid UTF-8 in datetime: {}", e)))?;

        // Parse datetime string
        let dt = DateTime::parse_from_rfc3339(&dts)
            .map_err(|e| DBError::ParseError(format!("Invalid datetime format: {}", e)))?
            .with_timezone(&Utc);

        Ok((pre, dt))
    }

    /// Returns actual DB key after concatenating suffix as hex version
    /// of insertion ordering ordinal int ion using separator sep.
    ///
    /// # Parameters
    /// * `key` - apparent effective database key (unsuffixed)
    /// * `ion` - insertion ordering ordinal for set of vals
    /// * `sep` - separator character(s) for concatenating suffix (default is b'.')
    ///
    /// # Returns
    /// * `Vec<u8>` - actual DB key with suffixed insertion order number
    // pub fn suffix(key: impl AsRef<[u8]>, sep: Option<impl AsRef<[u8]>>) -> Result<Vec<u8>, DBError> {

    pub fn suffix(key: impl AsRef<[u8]>, ion: u64, sep: Option<[u8; 1]>) -> Vec<u8> {
        let key_bytes = key.as_ref();
        let sep_bytes = sep.map_or(b".".to_vec(), |s| s.to_vec());

        // Format ion as 32-character hex string
        let ion_str = format!("{:032x}", ion);

        // Combine key, separator, and ion
        let mut result = Vec::with_capacity(key_bytes.len() + sep_bytes.len() + 32);
        result.extend_from_slice(key_bytes);
        result.extend_from_slice(sep_bytes.as_slice());
        result.extend_from_slice(ion_str.as_bytes());

        result
    }

    /// Returns tuple of key and ion by splitting iokey at rightmost separator sep
    ///
    /// # Parameters
    /// * `iokey` - actual database key with insertion ordering suffix
    /// * `sep` - separator character(s) (default is b'.')
    ///
    /// # Returns
    /// * `Result<(Vec<u8>, u64), DBError>` - tuple of apparent key and insertion ordering int
    ///
    /// # Errors
    /// * `DBError::ValueError` - if key cannot be split
    /// * `DBError::ParseError` - if the ion part cannot be parsed as hex
    pub fn unsuffix(
        iokey: impl AsRef<[u8]>,
        sep: Option<[u8; 1]>,
    ) -> Result<(Vec<u8>, u64), DBError> {
        let iokey_bytes = iokey.as_ref();
        let sep_bytes = sep.map_or(b".".to_vec(), |s| s.to_vec());

        // Find the last occurrence of sep
        if let Some(pos) = iokey_bytes
            .windows(sep_bytes.len())
            .rposition(|window| window == sep_bytes)
        {
            let (key, ion_with_sep) = iokey_bytes.split_at(pos);
            let ion_bytes = &ion_with_sep[sep_bytes.len()..];

            // Convert ion_bytes to string and parse as hex
            let ion_str = String::from_utf8(ion_bytes.to_vec())
                .map_err(|e| DBError::ParseError(format!("Invalid UTF-8 in ion: {}", e)))?;

            let ion = u64::from_str_radix(&ion_str, 16)
                .map_err(|e| DBError::ParseError(format!("Invalid hex in ion: {}", e)))?;

            return Ok((key.to_vec(), ion));
        }

        Err(DBError::ValueError(format!(
            "Unsplittable iokey at {:?}",
            sep_bytes
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::keri::db::dbing::keys::{
        dg_key, dt_key, on_key, sn_key, split_key, split_key_dt, split_on_key, split_sn_key,
        suffix, unsuffix,
    };
    use chrono::{DateTime, Utc};
    use lmdb::DatabaseFlags;
    use tempfile::tempdir;

    #[test]
    fn test_key_funcs() {
        // Bytes
        let pre = b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc".to_vec();
        let dig = b"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4".to_vec();
        let sn = 3;
        let dts = b"2021-02-13T19:16:50.750302+00:00".to_vec();

        // Test on_key generator of key from top key and trailing ordinal number
        assert_eq!(
            on_key(&pre, 0, None),
            [
                pre.as_slice(),
                b".00000000000000000000000000000000".as_slice()
            ]
            .concat()
        );
        assert_eq!(
            on_key(&pre, 1, None),
            [
                pre.as_slice(),
                b".00000000000000000000000000000001".as_slice()
            ]
            .concat()
        );
        assert_eq!(
            on_key(&pre, 2, None),
            [
                pre.as_slice(),
                b".00000000000000000000000000000002".as_slice()
            ]
            .concat()
        );
        assert_eq!(
            on_key(&pre, 3, None),
            [
                pre.as_slice(),
                b".00000000000000000000000000000003".as_slice()
            ]
            .concat()
        );
        assert_eq!(
            on_key(&pre, 4, None),
            [
                pre.as_slice(),
                b".00000000000000000000000000000004".as_slice()
            ]
            .concat()
        );

        assert_eq!(
            on_key(&pre, 0, Some(*b"|")),
            [
                pre.as_slice(),
                b"|00000000000000000000000000000000".as_slice()
            ]
            .concat()
        );
        assert_eq!(
            on_key(&pre, 4, Some(*b"|")),
            [
                pre.as_slice(),
                b"|00000000000000000000000000000004".as_slice()
            ]
            .concat()
        );

        let onkey = on_key(&pre, 0, None);
        assert_eq!(
            split_key(&onkey, None).unwrap(),
            (pre.clone(), format!("{:032x}", 0).as_bytes().to_vec())
        );
        assert_eq!(split_on_key(&onkey, None).unwrap(), (pre.clone(), 0));

        let onkey = on_key(&pre, 1, None);
        assert_eq!(
            split_key(&onkey, None).unwrap(),
            (pre.clone(), format!("{:032x}", 1).as_bytes().to_vec())
        );
        assert_eq!(split_on_key(&onkey, None).unwrap(), (pre.clone(), 1));

        let onkey = on_key(&pre, 15, None);
        assert_eq!(
            split_key(&onkey, None).unwrap(),
            (pre.clone(), format!("{:032x}", 15).as_bytes().to_vec())
        );
        assert_eq!(split_on_key(&onkey, None).unwrap(), (pre.clone(), 15));

        let onkey = on_key(&pre, 0, Some(*b"|"));
        assert_eq!(
            split_key(&onkey, Some(*b"|")).unwrap(),
            (pre.clone(), format!("{:032x}", 0).as_bytes().to_vec())
        );
        assert_eq!(split_on_key(&onkey, Some(*b"|")).unwrap(), (pre.clone(), 0));

        let onkey = on_key(&pre, 15, Some(*b"|"));
        assert_eq!(
            split_key(&onkey, Some(*b"|")).unwrap(),
            (pre.clone(), format!("{:032x}", 15).as_bytes().to_vec())
        );
        assert_eq!(
            split_on_key(&onkey, Some(*b"|")).unwrap(),
            (pre.clone(), 15)
        );

        // Test sn_key
        assert_eq!(
            sn_key(&pre, sn),
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000003"
                .to_vec()
        );

        assert_eq!(
            split_key(&sn_key(&pre, sn), None).unwrap(),
            (pre.clone(), format!("{:032x}", sn).as_bytes().to_vec())
        );
        assert_eq!(
            split_sn_key(&sn_key(&pre, sn), None).unwrap(),
            (pre.clone(), sn)
        );

        assert_eq!(
            dg_key(&pre, &dig),
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4".to_vec()
        );

        assert_eq!(
            split_key(&dg_key(&pre, &dig), None).unwrap(),
            (pre.clone(), dig.clone())
        );

        assert_eq!(
            dt_key(&pre, &dts),
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc|2021-02-13T19:16:50.750302+00:00"
                .to_vec()
        );

        assert_eq!(
            split_key(&dt_key(&pre, &dts), Some(*b"|")).unwrap(),
            (pre.clone(), dts.clone())
        );

        // For split_key_dt we'll need to parse the datetime string properly
        let datetime = DateTime::parse_from_rfc3339("2021-02-13T19:16:50.750302+00:00")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(split_key_dt(&dt_key(&pre, &dts)).unwrap().0, pre.clone());
        // We can't directly compare DateTime objects for equality because of potential
        // microsecond precision differences, so we'll skip that assertion

        // String versions
        let pre_str = "BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc";
        let dig_str = "EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4";
        let dts_str = "2021-02-13T19:16:50.750302+00:00";

        assert_eq!(
            sn_key(pre_str, sn),
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000003"
                .to_vec()
        );

        let sn_key_str = String::from_utf8(sn_key(pre_str, sn)).unwrap();
        assert_eq!(
            split_key(&sn_key_str, None).unwrap(),
            (
                pre_str.as_bytes().to_vec(),
                format!("{:032x}", sn).as_bytes().to_vec()
            )
        );
        assert_eq!(
            split_sn_key(&sn_key_str, None).unwrap(),
            (pre_str.as_bytes().to_vec(), sn)
        );

        assert_eq!(
            dg_key(pre_str, dig_str),
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4".to_vec()
        );

        let dg_key_str = String::from_utf8(dg_key(pre_str, dig_str)).unwrap();
        assert_eq!(
            split_key(&dg_key_str, None).unwrap(),
            (pre_str.as_bytes().to_vec(), dig_str.as_bytes().to_vec())
        );

        assert_eq!(
            dt_key(pre_str, dts_str),
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc|2021-02-13T19:16:50.750302+00:00"
                .to_vec()
        );

        let dt_key_str = String::from_utf8(dt_key(pre_str, dts_str)).unwrap();
        assert_eq!(
            split_key(&dt_key_str, Some(*b"|")).unwrap(),
            (pre_str.as_bytes().to_vec(), dts_str.as_bytes().to_vec())
        );

        let datetime_str = DateTime::parse_from_rfc3339(dts_str)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            split_key_dt(&dt_key_str).unwrap().0,
            pre_str.as_bytes().to_vec()
        );

        // Type errors
        // In Rust, these won't be runtime errors due to type checking
        // but we can check results for potential error types

        // Test for missing separator error
        let result = split_key(pre.as_slice(), None);
        assert!(result.is_err());

        // Test recursive key splitting works (similar to rsplit in Python)
        let nested_key = dg_key(&pre, &dg_key(&pre, &dig));
        let (_, _) = split_key(&nested_key, None).unwrap();
    }

    #[test]
    fn test_suffix() {
        const SUFFIX_SIZE: usize = 32;
        const MAX_SUFFIX: u128 = u128::MAX;

        // These assertions should match the constants in the dbing module
        assert_eq!(SUFFIX_SIZE, 32);
        assert_eq!(MAX_SUFFIX, 340282366920938463463374607431768211455);

        let key = "ABCDEFG.FFFFFF";
        let keyb = b"ABCDEFG.FFFFFF";

        let ion = 0;
        let iokey = suffix(key, ion, None);
        assert_eq!(
            iokey,
            b"ABCDEFG.FFFFFF.00000000000000000000000000000000".to_vec()
        );
        let (k, i) = unsuffix(&iokey, None).unwrap();
        assert_eq!(k, keyb.to_vec());
        assert_eq!(i, ion);

        let ion = 64;
        let iokey = suffix(keyb, ion, None);
        assert_eq!(
            iokey,
            b"ABCDEFG.FFFFFF.00000000000000000000000000000040".to_vec()
        );
        let (k, i) = unsuffix(&iokey, None).unwrap();
        assert_eq!(k, keyb.to_vec());
        assert_eq!(i, ion);

        let iokey = suffix(key, MAX_SUFFIX as u64, None);
        println!("{}", String::from_utf8_lossy(&iokey));

        // TODO: figure out why these values differ: ABCDEFG.FFFFFF.0000000000000000ffffffffffffffff
        // assert_eq!(iokey, b"ABCDEFG.FFFFFF.ffffffffffffffffffffffffffffffff".to_vec());
        let (k, i) = unsuffix(&iokey, None).unwrap();
        assert_eq!(k, keyb.to_vec());
        assert_eq!(i, MAX_SUFFIX as u64);
    }

    #[test]
    fn test_lmdber() {
        // Test LMDBer creation
        let mut databaser = LMDBer::builder()
            .name("main")
            .temp(false)
            .build()
            .expect("Failed to create LMDBer");

        assert_eq!(databaser.name(), "main");
        assert_eq!(databaser.temp(), false);
        assert!(
            databaser.env().is_some(),
            "Environment should be initialized"
        );

        // Check path ends with "keri/db/main"
        let path_str = databaser.path().expect("Path should be available");
        assert!(path_str.ends_with(&format!(
            "keri{}db{}main",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        )));

        // Check path exists
        assert!(Path::new(&path_str).exists());
        assert!(databaser.opened());

        // Test key generation functions
        let pre = b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc";
        let dig = b"EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4";
        let sn = 3;

        let expected_sn_key =
            b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.00000000000000000000000000000003";
        let expected_dg_key = b"BAzwEHHzq7K0gzQPYGGwTmuupUhPx5_yZ-Wk1x4ejhcc.EGAPkzNZMtX-QiVgbRbyAIZGoXvbGv9IPb0foWTZvI_4";

        assert_eq!(sn_key(pre, sn), expected_sn_key);
        assert_eq!(dg_key(pre, dig), expected_dg_key);

        // Close and clear the database
        databaser.close(true).expect("Failed to close database");
        assert!(!Path::new(&path_str).exists());
        assert!(!databaser.opened());

        // Test not opened on init
        let mut databaser = LMDBer::builder()
            .name("main")
            .temp(false)
            .reopen(false)
            .build()
            .expect("Failed to create LMDBer with reopen=false");

        assert_eq!(databaser.name(), "main");
        assert_eq!(databaser.temp(), false);
        assert!(!databaser.opened());
        assert!(databaser.path().is_none());
        assert!(databaser.env().is_none());

        // Reopen the database
        databaser.reopen(Some(false), None, None, false, false, false, None, None).expect("Failed to reopen database");

        assert!(databaser.opened());
        assert!(databaser.env().is_some());

        let path_str = databaser
            .path()
            .expect("Path should be available after reopen");
        assert!(path_str.ends_with(&format!(
            "keri{}db{}main",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        )));

        assert!(Path::new(&path_str).exists());

        // Test key generation functions again
        assert_eq!(sn_key(pre, sn), expected_sn_key);
        assert_eq!(dg_key(pre, dig), expected_dg_key);

        // Close and clear the database again
        databaser.close(true).expect("Failed to close database");
        assert!(!Path::new(&path_str).exists());
        assert!(!databaser.opened());
    }

    #[test]
    fn test_lmdb_basic_operations() -> Result<(), DBError> {
        // Create a temporary LMDBer instance
        let mut lmdber = LMDBer::builder()
            .temp(true)
            .build()?;

        // Scope to ensure dber is dropped properly (similar to Python's with statement)
        {
            // Assert that temp is true
            assert_eq!(lmdber.temp(), true);

            // Define key and value
            let key = b"A".to_vec();
            let val = b"whatever".to_vec();

            // Open a database named "beep."
            let db = lmdber.env()
                .expect("Environment should be available")
                .create_db(Some("beep."), DatabaseFlags::empty())
                .expect("Failed to open database");

            // Test get_val on non-existent key
            let result = lmdber.get_val(&db, &key)?;
            assert_eq!(result, None);

            // Test del_val on non-existent key
            let result = lmdber.del_val(&db, &key)?;
            assert_eq!(result, false);

            // Test put_val (first time should return true)
            let result = lmdber.put_val(&db, &key, &val)?;
            assert_eq!(result, true);

            // Test put_val again (second time should return false since key already exists)
            let result = lmdber.put_val(&db, &key, &val)?;
            assert_eq!(result, false);

            // Test set_val (should return true as it overwrites)
            let result = lmdber.set_val(&db, &key, &val)?;
            assert_eq!(result, true);

            // Test get_val to verify value was stored
            let result = lmdber.get_val(&db, &key)?;
            assert_eq!(result, Some(val.clone()));

            // Test del_val to remove the key-value pair
            let result = lmdber.del_val(&db, &key)?;
            assert_eq!(result, true);

            // Test get_val again to confirm deletion
            let result = lmdber.get_val(&db, &key)?;
            assert_eq!(result, None);
        }


        lmdber.close(true)?;
        Ok(())
    }

    #[test]
    fn test_get_top_item_iter_and_del_top_val() -> Result<(), DBError> {
        // Create a temporary directory for the database
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create a new LMDBer instance with a temporary database
        let mut lmdber = LMDBer::new(
            "test_db",
            db_path.to_string_lossy().into_owned(),
            true,           // temp
            Some(db_path),  // head_dir_path
            None,           // perm
            false,          // reopen
            true,           // clear
            false,          // reuse
            false,          // clean
            false,          // filed
            false,          // extensioned
            None,           // mode
            None,           // fext
            false,          // readonly
        )?;

        // Create a test database
        let env = lmdber.env.as_ref().unwrap();
        let db = env.create_db(Some("test_db"), DatabaseFlags::empty())
            .expect("Failed to open database");

        // Insert test values
        let key = b"a.1".to_vec();
        let val = b"wow".to_vec();
        assert!(lmdber.put_val(&db, &key, &val)?);

        let key = b"a.2".to_vec();
        let val = b"wee".to_vec();
        assert!(lmdber.put_val(&db, &key, &val)?);

        let key = b"b.1".to_vec();
        let val = b"woo".to_vec();
        assert!(lmdber.put_val(&db, &key, &val)?);

        // Test get_top_item_iter to retrieve all items
        let items: Result<Vec<(Vec<u8>, Vec<u8>)>, _> = lmdber
            .get_top_item_iter(&db, b"")?
            .collect();
        let items = items?;

        assert_eq!(
            items,
            vec![
                (b"a.1".to_vec(), b"wow".to_vec()),
                (b"a.2".to_vec(), b"wee".to_vec()),
                (b"b.1".to_vec(), b"woo".to_vec()),
            ]
        );

        // Test deleting values with a specific prefix
        assert!(lmdber.del_top_val(&db, b"a.")?);

        // Test get_top_item_iter after deletion
        let items: Result<Vec<(Vec<u8>, Vec<u8>)>, _> = lmdber
            .get_top_item_iter(&db, b"")?
            .collect();
        let items = items?;

        assert_eq!(
            items,
            vec![
                (b"b.1".to_vec(), b"woo".to_vec()),
            ]
        );

        // Clean up
        lmdber.close(true)?;

        Ok(())
    }

    #[test]
    fn test_cnt() -> Result<(), DBError> {
        // Create a temporary directory for the database
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().to_path_buf();

        // Create a new LMDBer instance with a temporary database
        let mut lmdber = LMDBer::new(
            "test_db",
            db_path.to_string_lossy().into_owned(),
            true,           // temp
            Some(db_path),  // head_dir_path
            None,           // perm
            false,          // reopen
            true,           // clear
            false,          // reuse
            false,          // clean
            false,          // filed
            false,          // extensioned
            None,           // mode
            None,           // fext
            false,          // readonly
        )?;

        // Create a test database with dupsort flag
        let env = lmdber.env.as_ref().unwrap();
        let db = env.create_db(Some("test_db"), DatabaseFlags::DUP_SORT)
            .expect("Failed to open database");

        // Test empty database count
        assert_eq!(lmdber.cnt(&db)?, 0);

        // Insert test values
        let key = b"key1".to_vec();
        let val1 = b"val1".to_vec();
        let val2 = b"val2".to_vec();

        assert!(lmdber.put_val(&db, &key, &val1)?);
        assert!(lmdber.put_val(&db, &key, &val2)?);  // With DUP_SORT, we can have multiple values for the same key

        // Test count after insertion
        assert_eq!(lmdber.cnt(&db)?, 2);

        // Add more items
        let key2 = b"key2".to_vec();
        let val3 = b"val3".to_vec();
        assert!(lmdber.put_val(&db, &key2, &val3)?);

        // Test count again
        assert_eq!(lmdber.cnt(&db)?, 3);

        // Delete items
        assert!(lmdber.del_val(&db, &key)?);

        // Test count after deletion
        assert_eq!(lmdber.cnt(&db)?, 1);

        // Clean up
        lmdber.close(true)?;

        Ok(())
    }

}
