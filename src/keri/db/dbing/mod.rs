pub mod keys;

use std::collections::HashSet;
use crate::keri::core::filing::{BaseFiler, Filer, FilerDefaults};
use crate::keri::db::errors::DBError;
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions};
use std::fs;
use std::ops::{Bound};
use std::path::PathBuf;
use std::sync::Arc;
use crate::keri::db::dbing::keys::{on_key, split_on_key, suffix, unsuffix};

const MAX_ON: u64 = u64::MAX;


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

// Define our database type
// Using a type alias for a database that stores bytes as both keys and values
type BytesDatabase = Database<heed::types::Bytes, heed::types::Bytes>;


/// LMDBer is a wrapper around LMDB database providing an interface similar to Filer
pub struct LMDBer {
    /// Base Filer instance
    pub filer: BaseFiler,

    /// LMDB environment
    pub env: Option<Arc<Env>>,

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

    pub fn env(&self) -> Option<&Arc<Env>> {
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
        let opened = self
            .filer
            .reopen(temp, head_dir_path, perm, clear, reuse, clean, mode, fext)
            .map_err(|e| DBError::FilerError(format!("{}", e)))?;

        // Close if already open
        if self.env.is_some() {
            self.close(false)?;
        }

        // Determine path
        let dir_path = match self.filer.path() {
            Some(p) => p,
            None => {
                return Err(DBError::PathError("Database path not set".into()));
            }
        };

        // Clear directory if needed
        if clear && !reuse {
            if let Err(e) = fs::remove_dir_all(&dir_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(DBError::IoError(format!("{}", e)));
                }
            }
            fs::create_dir_all(&dir_path).map_err(|e| DBError::FilerError(format!("{}", e)))?;
        }

        // Open environment with heed
        let mut env_builder = EnvOpenOptions::new();

        // Configure environment
        env_builder
            .map_size(Self::MAP_SIZE)
            .max_dbs(Self::MAX_NAMED_DBS);


        let env = if self.readonly {
            unsafe { Arc::new(env_builder.open(&dir_path)?) }
        } else {
            unsafe { Arc::new(env_builder.open(&dir_path)?) }
        };

        self.env = Some(env);

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

    pub fn close(&mut self, clear: bool) -> Result<bool, DBError> {
        if let Some(env) = self.env.take() {
            // With heed, we don't need to explicitly close the environment.
            // It will be closed when dropped.
            drop(env);
        }
        self.env = None;

        // Clear the directory if needed
        if clear && self.filer.path().is_some() {
            let path = self.filer.path().unwrap();
            if let Err(e) = fs::remove_dir_all(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(DBError::IoError(format!("{}", e)));
                }
            }
        }

        let result = self.filer
            .close(clear)
            .map_err(|e| DBError::FilerError(format!("{}", e)))?;

        Ok(result)
    }

    // Database operations with heed

    // Create a database
    pub fn create_database(&self, name: Option<&str>, dup_sort: Option<bool>) -> Result<BytesDatabase, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let mut txn = env.write_txn()?;
        let dup_sort = dup_sort.unwrap_or(false);

        let mut binding = env
            .database_options()
            .types::<heed::types::Bytes, heed::types::Bytes>();
        let options = binding
            .name(name.unwrap_or(""));

        if dup_sort {
            options.flags(DatabaseFlags::DUP_SORT);
        }

        let db = options.create(&mut txn)?;

        txn.commit()?;
        Ok(db)
    }

    // Open an existing database
    pub fn open_database(&self, name: Option<&str>) -> Result<Option<BytesDatabase>, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let mut wtxn = env.write_txn()?;

        let db = env.open_database(&mut wtxn, name)?;

        wtxn.commit()?;
        Ok(db)
    }

    // Get a value
    pub fn len(&self, db: &BytesDatabase) -> Result<u64, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let rtxn = env.read_txn()?;

        let result = match db.len(&rtxn) {
            Ok(val) => {val}
            Err(_) => {0}
        };

        Ok(result)
    }

    // Put a value
    pub fn put_val(&self, db: &BytesDatabase, key: &[u8], val: &[u8]) -> Result<bool, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // First check if the key already exists using a read transaction
        let rtxn = env.read_txn()?;
        let key_exists = db.get(&rtxn, key)?.is_some();
        rtxn.commit()?;

        // If key already exists, return false (didn't add)
        if key_exists {
            return Ok(false);
        }

        // If key doesn't exist, add it with a write transaction
        let mut wtxn = env.write_txn()?;
        db.put(&mut wtxn, key, val)?;
        wtxn.commit()?;

        // Return true to indicate the value was successfully added
        Ok(true)
    }

    // Same as put_val, kept for compatibility
    pub fn set_val(&self, db: &BytesDatabase, key: &[u8], val: &[u8]) -> Result<bool, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let mut wtxn = env.write_txn()?;
        db.put(&mut wtxn, key, val)?;
        wtxn.commit()?;
        Ok(true)
    }

    // Get a value
    pub fn get_val(&self, db: &BytesDatabase, key: &[u8]) -> Result<Option<Vec<u8>>, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let rtxn = env.read_txn()?;

        let result = match db.get(&rtxn, key)? {
            Some(val) => Some(val.to_vec()),
            None => None,
        };

        Ok(result)
    }

    // Delete a value
    pub fn del_val(&self, db: &BytesDatabase, key: &[u8]) -> Result<bool, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let mut wtxn = env.write_txn()?;

        let exists = db.get(&wtxn, key)?.is_some();
        if exists {
            db.delete(&mut wtxn, key)?;
            wtxn.commit()?;
            Ok(true)
        } else {
            wtxn.abort();
            Ok(false)
        }
    }

    // Count entries in a database
    pub fn cnt(&self, db: &BytesDatabase) -> Result<usize, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let rtxn = env.read_txn()?;

        // In heed 0.22.0, we can iterate to count
        let mut count = 0;
        let iter = db.iter(&rtxn)?;
        for _ in iter {
            count += 1;
        }

        Ok(count)
    }

    /// Get items with a given prefix and process them with a callback function
    ///
    /// # Parameters
    /// - `db`: The database to search in
    /// - `prefix`: The prefix to match keys against
    /// - `cb`: Callback function that takes key-value pairs
    ///
    /// # Returns
    /// - `Ok(count)`: Number of items processed
    /// - `Err(DBError)`: If a database error occurs
    pub fn get_top_items_iter<F>(&self, db: &BytesDatabase, prefix: &[u8], cb: F) -> Result<usize, DBError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<bool, DBError>,
    {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let txn = env.read_txn()?;

        // Get an iterator over all items in the database
        let iter = db.iter(&txn)?;

        // Process items with the callback
        let mut count = 0;
        let mut callback = cb;

        for result in iter {
            match result {
                Ok((k, v)) => {
                    // Only process items with matching prefix
                    if k.starts_with(prefix) {
                        count += 1;

                        // Call the callback with the key-value pair
                        // If callback returns false, stop iteration
                        if !callback(&k, &v)? {
                            break;
                        }
                    }
                },
                Err(e) => return Err(DBError::EnvError(e)),
            }
        }

        Ok(count)
    }

    // Delete all values with a given prefix
    pub fn del_top_val(&self, db: &BytesDatabase, prefix: &[u8]) -> Result<bool, DBError> {
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        let mut txn = env.write_txn()?;

        // First collect keys with the prefix
        let read_txn = env.read_txn()?;
        let iter = db.iter(&read_txn)?;

        let keys_to_delete: Vec<Vec<u8>> = iter
            .filter_map(|result| {
                match result {
                    Ok((k, _)) => {
                        if k.starts_with(prefix) {
                            Some(Ok(k.to_vec()))
                        } else {
                            None
                        }
                    },
                    Err(e) => Some(Err(DBError::EnvError(e))),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Close read transaction before starting write operations
        drop(read_txn);

        let mut deleted = false;
        if !keys_to_delete.is_empty() {
            for key in keys_to_delete {
                db.delete(&mut txn, &key)?;
                deleted = true;
            }

            txn.commit()?;
        } else {
            txn.abort();
        }

        Ok(deleted)
    }

    /// Write serialized bytes val to location at onkey consisting of
    /// key + sep + serialized on in db.
    /// Overwrites pre-existing value at onkey if any.
    ///
    /// # Parameters
    /// - `db`: Named sub database in LMDB
    /// - `key`: Key within sub db's keyspace
    /// - `on`: Ordinal number at which to write
    /// - `val`: Bytes to be written at onkey
    /// - `sep`: Separator byte for constructing the composite key
    ///
    /// # Returns
    /// - `Ok(true)`: If successful write (i.e., onkey not already in db)
    /// - `Ok(false)`: Otherwise
    /// - `Err(DBError)`: If a database error occurs
    pub fn set_on_val(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        on: Option<u64>,
        val: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<bool, DBError> {
        let sep = sep.unwrap_or(*b".");
        let on = on.unwrap_or(0);

        // Get the environment
        let env = self.env.as_ref().ok_or(DBError::DatabaseError("Not opened".to_string()))?;

        // Begin a write transaction
        let mut txn = env.write_txn().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;

        // Create the onkey (composite key with ordinal number)
        let onkey = if !key.is_empty() {
            on_key(key, on, Some(sep))
        } else {
            key.to_vec()
        };

        // Put the value at the onkey
        if onkey.is_empty() {
            return Err(DBError::KeyError("Key cannot be empty".to_string()));
        }

        let result = match db.put(&mut txn, &onkey, val) {
            Ok(_) => true,
            Err(e) => {
                if let Some(_) = e.to_string().to_lowercase().find("valsize") {
                    return Err(DBError::KeyError(format!(
                        "Key: `{:?}` is either empty, too big (for lmdb), or wrong DUPFIXED size.",
                        onkey
                    )));
                }
                return Err(DBError::DatabaseError(format!("{}", e)));
            }
        };

        // Commit the transaction
        txn.commit().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;

        Ok(result)
    }

    /// Appends val in order after last previous onkey in db where
    /// onkey has same given key prefix but with different serialized on suffix
    /// attached with sep.
    ///
    /// Returns ordinal number on, of appended entry. Appended on is 1 greater
    /// than previous latest on at key.
    ///
    /// Works with either dupsort==True or False since always creates new full key.
    ///
    /// # Parameters
    /// - `db`: Named sub database in LMDB
    /// - `key`: Key within sub db's keyspace
    /// - `val`: Bytes to be written at onkey
    /// - `sep`: Separator byte for constructing the composite key
    ///
    /// # Returns
    /// - `Ok(on)`: Ordinal number of newly appended val
    /// - `Err(DBError)`: If a database error occurs
    pub fn append_on_val(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        val: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<u64, DBError> {
        let sep = sep.unwrap_or([b'.']);

        // Get the environment
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;
        // Initialize with default ordinal 0
        let mut on = 0;
        let onkey = on_key(key, 0, Some(sep));

        // Create a range iterator to find keys with the given prefix
        // The iterator will return keys in ascending order

        let rtxn = env.read_txn()?;
        let range = (Bound::Included(onkey.as_slice()), Bound::Unbounded);

        let mut iter = db.range(&rtxn, &range)?;
        let mut last_entry = None;

        for result in iter {
            let (onkey, _) = result?;
            let (ckey, cn) = split_on_key(onkey.as_ref(), Some(sep))?;
            if ckey != key {
                break
            }
            last_entry = Some(cn);
        }
        // If we found a last entry, increment its ordinal number
        if let Some(last_on) = last_entry {
            // Check for overflow
            if last_on == MAX_ON {
                return Err(DBError::ValueError(format!(
                    "Number part on={} for key part key={:?} exceeds maximum size.",
                    last_on, key
                )));
            }
            on = last_on + 1;
        }

        // Create the new key with the determined ordinal number
        let onkey = on_key(key, on, Some(sep));

        // Use a write transaction to add the new entry
        let mut wtxn = env.write_txn()?;

        // Check if the key already exists (should not happen if our algorithm is correct)
        if db.get(&wtxn, &onkey)?.is_some() {
            return Err(DBError::ValueError(format!(
                "Key already exists: {:?}", onkey
            )));
        }

        // Put the value at the onkey
        db.put(&mut wtxn, &onkey, val)?;

        // Commit the transaction
        wtxn.commit()?;

        Ok(on)
    }

    /// Write serialized bytes val to location at onkey consisting of
    /// key + sep + serialized on in db.
    /// Does not overwrite.
    ///
    /// # Returns
    /// - Result<bool, DBError>: True if successful write i.e onkey not already in db,
    ///                          False otherwise
    ///
    /// # Parameters
    /// - db: named sub db of lmdb
    /// - key: key within sub db's keyspace plus trailing part on
    /// - on: ordinal number at which write
    /// - val: to be written at onkey
    /// - sep: separator bytes for split
    pub fn put_on_val(&self, db: &BytesDatabase, key: &[u8], on: u32, val: &[u8], sep: Option<[u8; 1]>) -> Result<bool, DBError> {
        let sep = sep.unwrap_or(*b".");
        let env = self.env.as_ref().ok_or(DBError::DatabaseError("Not opened".to_string()))?;
        let mut txn = env.write_txn().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;

        let onkey = if !key.is_empty() {
            on_key(key, on as u64, Some(sep))
        } else {
            key.to_vec()
        };

        // First check if the key already exists using a read transaction
        let rtxn = env.read_txn()?;
        let key_exists = db.get(&rtxn, &onkey)?.is_some();
        rtxn.commit()?;

        // If key already exists, return false (didn't add)
        if key_exists {
            return Ok(false);
        }

        db.put(&mut txn, &onkey, val)
            .map_err(|e| {
                if let heed::Error::Mdb(heed::MdbError::BadValSize) = e {
                    DBError::ValueError(format!("Key: `{:?}` is either empty, too big, or wrong DUPFIXED size", onkey))
                } else {
                    DBError::DatabaseError(format!("{}", e))
                }
            })?;

        txn.commit().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;
        Ok(true)
    }

    /// Gets value at onkey consisting of key + sep + serialized on in db.
    ///
    /// # Returns
    /// - Result<Option<Vec<u8>>, DBError>: entry at onkey or None if no entry at key
    ///
    /// # Parameters
    /// - db: named sub db of lmdb
    /// - key: key within sub db's keyspace
    /// - on: ordinal number at which to retrieve
    /// - sep: separator bytes for split
    pub fn get_on_val(&self, db: &BytesDatabase, key: &[u8], on: u32, sep: Option<[u8; 1]>) -> Result<Option<Vec<u8>>, DBError> {
        let sep = sep.unwrap_or(*b".");
        let env = self.env.as_ref().ok_or(DBError::DatabaseError("Not opened".to_string()))?;
        let txn = env.read_txn().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;

        let onkey = if !key.is_empty() {
            on_key(key, on as u64, Some(sep))
        } else {
            key.to_vec()
        };

        match db.get(&txn, &onkey).map_err(|e| {
            if let heed::Error::Mdb(heed::MdbError::BadValSize) = e {
                DBError::ValueError(format!("Key: `{:?}` is either empty, too big, or wrong DUPFIXED size", onkey))
            } else {
                DBError::DatabaseError(format!("{}", e))
            }
        })? {
            Some(val) => Ok(Some(val.to_vec())),
            None => Ok(None),
        }
    }

    /// Deletes value at onkey consisting of key + sep + serialized on in db.
    ///
    /// # Returns
    /// - Result<bool, DBError>: True if key exists in database Else False
    ///
    /// # Parameters
    /// - db: named sub db of lmdb
    /// - key: key within sub db's keyspace
    /// - on: ordinal number at which to delete
    /// - sep: separator bytes for split
    pub fn del_on_val(&self, db: &BytesDatabase, key: &[u8], on: u32, sep: Option<[u8; 1]>) -> Result<bool, DBError> {
        let sep = sep.unwrap_or(*b".");
        let env = self.env.as_ref().ok_or(DBError::DatabaseError("Not opened".to_string()))?;
        let mut txn = env.write_txn().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;

        let onkey = if !key.is_empty() {
            on_key(key, on as u64, Some(sep))
        } else {
            key.to_vec()
        };

        let result = db.delete(&mut txn, &onkey)
            .map_err(|e| {
                if let heed::Error::Mdb(heed::MdbError::BadValSize) = e {
                    DBError::ValueError(format!("Key: `{:?}` is either empty, too big, or wrong DUPFIXED size", onkey))
                } else {
                    DBError::DatabaseError(format!("{}", e))
                }
            })?;

        txn.commit().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;
        Ok(result)
    }

    /// Returns count of all ordinal keyed vals with key but different on tail in db
    /// starting at ordinal number on of key.
    ///
    /// # Returns
    /// - Result<usize, DBError>: count of matching entries
    ///
    /// # Parameters
    /// - db: named sub db of lmdb
    /// - key: key within sub db's keyspace (when empty, counts whole db)
    /// - on: ordinal number at which to initiate count
    /// - sep: separator bytes for split
    pub fn cnt_on_vals(
        &self,
        db: &BytesDatabase,
        key: Option<&[u8]>,
        on: Option<u64>,
        sep: Option<[u8; 1]>,
    ) -> Result<usize, DBError> {
        let separator = sep.unwrap_or([b'.']);
        let key = key.unwrap_or(&[]);
        let on = on.unwrap_or(0);

        // Get environment from the Arc
        let env = self.env.as_ref().ok_or(DBError::DatabaseError("Environment not available".to_string()))?;

        let mut count = 0;

        let txn = env.read_txn()?;

        // Create the starting key for the range
        let iter = if !key.is_empty() {
            let onkey = on_key(key, on, Some(separator));
            let range = (Bound::Included(onkey.as_slice()), Bound::Unbounded);
            db.range(&txn, &range)?
        } else {
            let range = (Bound::Unbounded, Bound::Unbounded);
            db.range(&txn, &range)?
        };

        // Use range method to iterate over keys starting from onkey

        for result in iter {
            let (ckey, cval) = result?;

            // Try to split the key to get the base part and the ordinal number
            match split_on_key(ckey.as_ref(), Some(separator)) {
                Ok((ckey_base, _)) => {
                    // If key is not empty and ckey_base doesn't match key, we've moved past our range
                    if !key.is_empty() && ckey_base != key {
                        break;
                    }
                    // Increment the count for valid entries
                    count += 1;
                },
                Err(_) => {
                    // Not a splittable key, we're done
                    println!("{:?} = {:?}", String::from_utf8(ckey.to_vec()), String::from_utf8(cval.to_vec()));
                    break;
                }
            }
        }

        Ok(count)
    }

    /// - txn: the read transaction to use
    pub fn get_on_item_iter<F>(
        &self,
        db: &BytesDatabase,
        key: Option<&[u8]>,
        on: Option<u64>,
        sep: Option<[u8; 1]>,
        mut callback: F
    )  -> Result<(), DBError>
    where
        F: FnMut(Vec<u8>, u64, Vec<u8>) -> Result<bool, DBError>,
    {
        let separator = sep.unwrap_or([b'.']);
        let key = key.unwrap_or(&[]);
        let on = on.unwrap_or(0);

        let env = self.env.as_ref().ok_or(DBError::DatabaseError("Not opened".to_string()))?;
        let txn = env.read_txn().map_err(|e| DBError::DatabaseError(format!("{}", e)))?;

        // Create the starting key for the range
        let mut iter = if !key.is_empty() {
            let onkey = on_key(key, on, Some(separator));
            let range = (Bound::Included(onkey.as_slice()), Bound::Unbounded);
            db.range(&txn, &range)?
        } else {
            let range = (Bound::Unbounded, Bound::Unbounded);
            db.range(&txn, &range)?
        };

        while let Some(result) = iter.next() {
            let (ckey, cval) = result?;

            // Split the key to get the base part and the ordinal number
            let (ckey_base, cn) = split_on_key(ckey.as_ref(), Some(separator))?;

            // If key is not empty and ckey_base doesn't match key, return an error
            // This will be caught in the take_while below to stop iteration
            if !key.is_empty() && ckey_base != key {
                break;
            }

            // Call the callback with each value
            // If callback returns false, stop iteration
            if !callback(ckey_base, cn, cval.to_vec())? {
                break;
            }
        }

        Ok(())
    }

    /// - txn: the read transaction to use
    pub fn get_on_val_iter<F>(
        &self,
        db: &BytesDatabase,
        key: Option<&[u8]>,
        on: Option<u64>,
        sep: Option<[u8; 1]>,
        mut callback: F
    )  -> Result<(), DBError>
    where
        F: FnMut(Vec<u8>) -> Result<bool, DBError>,
    {
        self.get_on_item_iter(&db, key, on, sep, |ckey, cn, cval| {
            callback(cval)
        })?;

        Ok(())
    }

    /// Add each val in vals to insertion ordered set of values all with the
    /// same apparent effective key for each val that is not already in set of
    /// vals at key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `vals`: Serialized values to add to set of vals at key
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(bool)`: True if added to set, false if already in set
    /// - `Err(DBError)`: If a database error occurs
    pub fn put_io_set_vals(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        vals: &[&[u8]],
        sep: Option<[u8; 1]>,
    ) -> Result<bool, DBError> {
        let sep = sep.unwrap_or([b'.']);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a write transaction
        let mut wtxn = env.write_txn()?;

        // Start with ordinal 0
        let mut ion = 0;
        let mut result = false;

        // Create a HashSet to track existing values at this key
        let mut existing_vals = HashSet::new();

        // Create a range to find all entries with this key
        let start_iokey = suffix(key, ion, Some(sep));

        // Use range to find all values with this key prefix
        let range = (Bound::Included(start_iokey.as_slice()), Bound::Unbounded);
        let iter = db.range(&wtxn, &range)?;

        // Track the highest ordinal number seen
        for entry in iter {
            let (iokey, val) = entry?;

            // Attempt to extract original key and ordinal
            if let (ckey, cion) = unsuffix(&iokey, Some(sep))? {
                if ckey == key {
                    // This is a value at our target key
                    existing_vals.insert(Vec::from(val));
                    ion = cion + 1; // ion to add at is increment of cion
                } else {
                    // We've moved past our key range
                    break;
                }
            }
        }

        // Process each value that's not already in the set
        for val in vals {
            if !existing_vals.contains(&Vec::from(*val)) {
                let iokey = suffix(key, ion, Some(sep));

                // Add the new entry
                db.put(&mut wtxn, &iokey, val)?;

                // Update result and increment ion for next value
                result = true;
                ion += 1;
            }
        }

        // Commit the transaction
        wtxn.commit()?;

        Ok(result)
    }

    /// Returns the insertion ordered set of values at the same apparent
    /// effective key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `ion`: starting ordinal value, default 0
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(Vec<Vec<u8>>)`: The ordered list of values at this key
    /// - `Err(DBError)`: If a database error occurs
    pub fn get_io_set_vals(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        ion: Option<u64>,
        sep: Option<[u8; 1]>,
    ) -> Result<Vec<Vec<u8>>, DBError> {
        let ion = ion.unwrap_or(0);
        let sep = sep.unwrap_or([b'.']);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a read transaction
        let rtxn = env.read_txn()?;

        // Initialize the result vector
        let mut vals = Vec::new();

        // Create the starting key for the range
        let start_iokey = suffix(key, ion, Some(sep));

        // Create a range to find all entries with this key starting from ion
        let range = (Bound::Included(start_iokey.as_slice()), Bound::Unbounded);
        let iter = db.range(&rtxn, &range)?;

        // Iterate through all entries in the range
        for entry in iter {
            let (iokey, val) = entry?;

            // Attempt to extract original key and ordinal
            if let (ckey, _) = unsuffix(&iokey, Some(sep))? {
                if ckey == key {
                    // This is a value at our target key
                    vals.push(Vec::from(val));
                } else {
                    // We've moved past our key range
                    break;
                }
            }
        }

        Ok(vals)
    }

    /// Add val idempotently to insertion ordered set of values all with the
    /// same apparent effective key if val not already in set of vals at key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `val`: Serialized value to add
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(bool)`: True if added to set, false if already in set
    /// - `Err(DBError)`: If a database error occurs
    pub fn add_io_set_val(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        val: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<bool, DBError> {
        let sep = sep.unwrap_or([b'.']);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a write transaction
        let mut wtxn = env.write_txn()?;

        // Initialize variables
        let mut ion = 0;
        let mut found = false;

        // Create the starting key for the range
        let start_iokey = suffix(key, ion, Some(sep));

        // Create a range to find all entries with this key
        let range = (Bound::Included(start_iokey.as_slice()), Bound::Unbounded);
        let iter = db.range(&wtxn, &range)?;

        // Iterate through all entries to check if the value exists and find the highest ion
        for entry in iter {
            let (iokey, cval) = entry?;

            // Attempt to extract original key and ordinal
            if let (ckey, cion) = unsuffix(&iokey, Some(sep))? {
                if ckey == key {
                    // This is a value at our target key
                    if cval == val {
                        found = true; // Value already exists in the set
                    }
                    ion = cion + 1; // ion to add at is increment of cion
                } else {
                    // We've moved past our key range
                    break;
                }
            }
        }

        // If the value is already in the set, return false
        if found {
            // Need to commit the transaction even though we're not making changes
            wtxn.commit()?;
            return Ok(false);
        }

        // Create the key with the next available ordinal
        let iokey = suffix(key, ion, Some(sep));

        // Add the new entry
        db.put(&mut wtxn, &iokey, val)?;

        // Commit the transaction
        wtxn.commit()?;

        Ok(true)
    }

    /// Deletes all values at apparent effective key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(bool)`: True if values were deleted at key, False if no values at key
    /// - `Err(DBError)`: If a database error occurs
    pub fn del_io_set_vals(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<bool, DBError> {
        let sep = sep.unwrap_or([b'.']);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a write transaction
        let mut wtxn = env.write_txn()?;

        // Initialize result
        let mut result = false;

        // Create the starting key for the range
        let start_iokey = suffix(key, 0, Some(sep));

        // First collect all the keys we need to delete
        // (We can't modify the database while iterating over it)
        let mut keys_to_delete = Vec::new();

        // Create a range to find all entries with this key
        let range = (Bound::Included(start_iokey.as_slice()), Bound::Unbounded);
        let iter = db.range(&wtxn, &range)?;

        // Collect keys to delete
        for entry in iter {
            let (iokey, _) = entry?;

            // Attempt to extract original key
            if let (ckey, _) = unsuffix(&iokey, Some(sep))? {
                if ckey == key {
                    // This is a value at our target key
                    keys_to_delete.push(iokey.to_vec());
                } else {
                    // We've moved past our key range
                    break;
                }
            }
        }

        // Now delete all the keys we found
        for iokey in keys_to_delete {
            result = true; // At least one key was deleted
            db.delete(&mut wtxn, &iokey)?;
        }

        // Commit the transaction
        wtxn.commit()?;

        Ok(result)
    }

    /// Deletes val at apparent effective key if exists.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// Because the insertion order of val is not provided must perform a linear
    /// search over set of values.
    ///
    /// Another problem is that vals may get added and deleted in any order so
    /// the max suffix ion may creep up over time. The suffix ordinal max > 2**16
    /// is an impossibly large number, however, so the suffix will not max out
    /// practically. But it's not the most elegant solution.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `val`: value to delete
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(bool)`: True if val was deleted at key, False if val not found at key
    /// - `Err(DBError)`: If a database error occurs
    pub fn del_io_set_val(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        val: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<bool, DBError> {
        let sep = sep.unwrap_or([b'.']);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a write transaction
        let mut wtxn = env.write_txn()?;

        // Create the starting key for the range
        let start_iokey = suffix(key, 0, Some(sep));

        // Create a range to find all entries with this key
        let range = (Bound::Included(start_iokey.as_slice()), Bound::Unbounded);
        let mut iter = db.range(&wtxn, &range)?;

        // First collect all the keys we need to delete
        // (We can't modify the database while iterating over it)
        let mut keys_to_delete = Vec::new();
        // Initialize result
        let mut result = false;

        // Search for the target value
        for entry in iter {
            let (iokey, cval) = entry?;

            // Attempt to extract original key
            if let (ckey, _) = unsuffix(&iokey, Some(sep))? {
                if ckey != key {
                    // We've moved past our key range
                    break;
                }

                if cval == val {
                    // Found the value, save it do delete later
                    keys_to_delete.push(iokey.to_vec());
                    break;
                }
            }
        }

        // Now delete all the keys we found
        for iokey in keys_to_delete {
            result = true; // At least one key was deleted
            db.delete(&mut wtxn, &iokey)?;
        }

        // Value not found, commit the transaction anyway
        wtxn.commit()?;

        Ok(result)
    }

    /// Erase all vals at key and then add unique vals as insertion ordered set of
    /// values all with the same apparent effective key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `vals`: Serialized values to add to set of vals at key
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(bool)`: True if values were added to set
    /// - `Err(DBError)`: If a database error occurs
    pub fn set_io_set_vals(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        vals: &[impl AsRef<[u8]>],
        sep: Option<[u8; 1]>,
    ) -> Result<bool, DBError> {
        let sep = sep.unwrap_or([b'.']);

        // First delete all existing values at this key
        self.del_io_set_vals(db, key, Some(sep))?;

        // If there are no values to add, return true (operation succeeded)
        if vals.is_empty() {
            return Ok(true);
        }

        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a write transaction
        let mut wtxn = env.write_txn()?;

        // Create a HashSet to eliminate duplicates while preserving order
        let mut unique_vals = Vec::new();
        let mut seen = HashSet::new();

        // Deduplicate values while preserving order
        for val in vals {
            let val_bytes = val.as_ref();
            // Only add if we haven't seen this value before
            if seen.insert(val_bytes.to_vec()) {
                unique_vals.push(val_bytes);
            }
        }

        // Add each unique value with ordinal suffix
        let mut result = false;
        for (i, val) in unique_vals.iter().enumerate() {
            let iokey = suffix(key, i as u64, Some(sep));
            db.put(&mut wtxn, &iokey, val)?;
            result = true;
        }

        // Commit the transaction
        wtxn.commit()?;

        Ok(result)
    }

    /// Count all values with the same apparent effective key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(usize)`: Count of values in set at apparent effective key
    /// - `Err(DBError)`: If a database error occurs
    pub fn cnt_io_set_vals(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<usize, DBError> {
        // Use the existing get_io_set_vals method and return the length of the result
        let vals = self.get_io_set_vals(db, key, None, sep)?;
        Ok(vals.len())
    }

    /// Returns an iterator over insertion ordered set of values at same apparent effective key.
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `ion`: Optional starting ordinal value, default 0
    /// - `sep`: Optional separator byte (defaults to '.')
    /// - `callback`: Function to call for each value found
    ///
    /// # Returns
    /// - `Ok(())`: If iteration completed successfully
    /// - `Err(DBError)`: If a database error occurs
    pub fn get_io_set_vals_iter<F>(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        ion: Option<u64>,
        sep: Option<[u8; 1]>,
        mut callback: F,
    ) -> Result<(), DBError>
    where
        F: FnMut(&[u8]) -> Result<bool, DBError>,
    {
        let sep = sep.unwrap_or([b'.']);
        let ion = ion.unwrap_or(0);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a read transaction
        let rtxn = env.read_txn()?;

        // Create the starting key for the range
        let start_iokey = suffix(key, ion, Some(sep));

        // Create a range to find all entries with this key starting from ion
        let range = (Bound::Included(start_iokey.as_slice()), Bound::Unbounded);
        let iter = db.range(&rtxn, &range)?;

        // Iterate through the entries and yield each value
        for entry in iter {
            let (iokey, val) = entry?;

            // Attempt to extract original key
            if let (ckey, _) = unsuffix(&iokey, Some(sep))? {
                if ckey != key {
                    // We've moved past our key range
                    break;
                }

                // Call the callback with the value
                // If callback returns false, stop iteration
                if !callback(&val)? {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Returns the last added value at the apparent effective key if any,
    /// otherwise None if no entry.
    ///
    /// Uses hidden ordinal key suffix for insertion ordering.
    /// The suffix is appended and stripped transparently.
    ///
    /// # Parameters
    /// - `db`: Instance of named sub db with dupsort==False
    /// - `key`: Apparent effective key
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(Option<Vec<u8>>)`: The last value if found, None otherwise
    /// - `Err(DBError)`: If a database error occurs
    pub fn get_io_set_val_last(
        &self,
        db: &BytesDatabase,
        key: &[u8],
        sep: Option<[u8; 1]>,
    ) -> Result<Option<Vec<u8>>, DBError> {
        let sep = sep.unwrap_or([b'.']);
        let env = self.env.as_ref().ok_or(DBError::DbClosed)?;

        // Create a read transaction
        let rtxn = env.read_txn()?;

        // Make iokey at max suffix value
        let max_iokey = suffix(key, u64::MAX, Some(sep));

        let mut ion = None; // No last value found yet

        // Create a range from our key to the end of the database
        let range = (Bound::Included(max_iokey.as_slice()), Bound::Unbounded);
        let mut iter = db.range(&rtxn, &range)?;

        // Check if max is past end of database
        if let Some(result) = iter.next() {
            let (entry_key, _) = result?;

            // Check if this entry is for our key or for a different key
            if let (ckey, cion) = unsuffix(&entry_key, Some(sep))? {
                if ckey == key {
                    // 1. Cursor at entry for the same key
                    ion = Some(cion);
                } else {
                    // 2. Other key after our key, need to look back

                    // Create a reverse range starting from our max key (exclusive)
                    let rev_range = (Bound::Unbounded, Bound::Excluded(max_iokey.as_slice()));
                    let mut rev_iter = db.rev_range(&rtxn, &rev_range)?;

                    // Check the first entry in reverse order
                    if let Some(result) = rev_iter.next() {
                        let (prev_key, _) = result?;

                        if let (ckey, cion) = unsuffix(&prev_key, Some(sep))? {
                            if ckey == key {
                                // Found a previous entry for our key
                                ion = Some(cion);
                            }
                        }
                    }
                }
            }
        } else {
            // Max is past end of database, check the last entry
            let rev_range = (Bound::Unbounded, Bound::Unbounded);
            let mut rev_iter = db.rev_range(&rtxn, &rev_range)?;

            if let Some(result) = rev_iter.next() {
                let (last_key, _) = result?;

                if let (ckey, cion) = unsuffix(&last_key, Some(sep))? {
                    if ckey == key {
                        // Last entry in db is for our key
                        ion = Some(cion);
                    }
                }
            }
        }

        // If we found a matching ion, get the value
        if let Some(ion) = ion {
            let iokey = suffix(key, ion, Some(sep));
            if let Some(val) = db.get(&rtxn, &iokey)? {
                return Ok(Some(val.to_vec()));
            }
        }

        // No matching value found
        Ok(None)
    }

    /// Get items with a given prefix from an IO set and process them with a callback function,
    /// stripping the insertion order suffix from keys before passing to the callback.
    ///
    /// # Parameters
    /// - `db`: The database to search in
    /// - `top`: The prefix to match keys against (empty for all items)
    /// - `cb`: Callback function that takes apparent key (with suffix removed) and value pairs
    /// - `sep`: Optional separator byte (defaults to '.')
    ///
    /// # Returns
    /// - `Ok(count)`: Number of items processed
    /// - `Err(DBError)`: If a database error occurs
    pub fn get_top_io_set_items_iter<F>(
        &self,
        db: &BytesDatabase,
        top: &[u8],
        sep: Option<[u8; 1]>,
        cb: F,
    ) -> Result<usize, DBError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<bool, DBError>,
    {
        let sep = sep.unwrap_or([b'.']);
        let mut callback = cb;
        let mut count = 0;

        // Use get_top_items to iterate through the prefixed items
        self.get_top_items_iter(db, top, |iokey, val| {
            // Split the iokey to get the apparent key without the suffix
            if let (key, _ion) = unsuffix(iokey, Some(sep))? {
                count += 1;
                // Call the callback with the apparent key and value
                callback(&key, val)
            } else {
                // Skip items that don't have a valid suffix
                Ok(true)
            }
        })?;

        Ok(count)
    }

}

impl Drop for LMDBer {
    fn drop(&mut self) {
        // Clean up resources when dropped
        let _ = self.close(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::keri::db::dbing::keys::{dg_key, sn_key};

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
            let db = lmdber.create_database(Some("beeb."), None).expect("Failed to create database");

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
        // Create a new LMDBer instance with a temporary database
        let mut lmdber = LMDBer::new(
            "test_db",
            "",
            true,           // temp
            None,           // head dir path
            None,           // perm
            true,          // reopen
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
        let db = lmdber.create_database(Some("test_db"), None).expect("Failed to open database");

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
        let mut items = Vec::new();
        lmdber.get_top_items_iter(&db, b"", |k, v| {
            items.push((k.to_vec(), v.to_vec()));
            Ok(true)
        })?;

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
        let mut items = Vec::new();
        lmdber.get_top_items_iter(&db, b"", |k, v| {
            items.push((k.to_vec(), v.to_vec()));
            Ok(true)
        })?;

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
        // Create a new LMDBer instance with a temporary database
        let mut lmdber = LMDBer::new(
            "test_db",
            "",
            true,           // temp
            None,  // head_dir_path
            None,           // perm
            true,          // reopen
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
        let db = lmdber.create_database(Some("test_db"), Some(true)).expect("Failed to open database");

        // Test empty database count
        assert_eq!(lmdber.cnt(&db)?, 0);

        // Insert test values
        let key0 = b"key0".to_vec();
        let key1 = b"key1".to_vec();
        let val1 = b"val1".to_vec();
        let val2 = b"val2".to_vec();

        assert!(lmdber.put_val(&db, &key0, &val1)?);
        assert!(lmdber.put_val(&db, &key1, &val2)?);  // With DUP_SORT, we can have multiple values for the same key

        // Test count after insertion
        assert_eq!(lmdber.cnt(&db)?, 2);

        // Add more items
        let key2 = b"key2".to_vec();
        let val3 = b"val3".to_vec();
        assert!(lmdber.put_val(&db, &key2, &val3)?);

        // Test count again
        assert_eq!(lmdber.cnt(&db)?, 3);

        // Delete items
        assert!(lmdber.del_val(&db, &key1)?);

        // Test count after deletion
        assert_eq!(lmdber.cnt(&db)?, 2);

        // Clean up
        lmdber.close(true)?;

        Ok(())
    }

    #[test]
    fn test_on_key_value_methods() -> Result<(), DBError> {
        // Set up a temporary directory for the test
        // Create a new LMDBer instance for testing
        let lmdber = LMDBer::builder()
            .name("test_db")
            .temp(true)
            .build()?;

        // Create "seen." database
        let db = lmdber.create_database(Some("seen."), None)?;

        // Define test prefixes and digests
        let pre_a = b"BBKY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc";
        let pre_b = b"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w";
        let pre_c = b"EIDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg";
        let pre_d = b"EAYC49i5zY_qrIZIicQgIDA1n-WiBA0A8YOqnKrB-wWQ";

        // Define separator
        let sep = *b".";
        let key_a0 = on_key(pre_a, 0, None);

        let key_b0 = on_key(pre_b, 0, None);
        let key_b1 = on_key(pre_b, 1, None);
        let key_b2 = on_key(pre_b, 2, None);
        let key_b3 = on_key(pre_b, 3, None);
        let key_b4 = on_key(pre_b, 4, None);

        let key_c0 = on_key(pre_c, 0, None);

        let dig_a = b"EA73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw";

        let dig_u = b"EB73b7reENuBahMJsMTLbeyyNPsfTRzKRWtJ3ytmInvw";
        let dig_v = b"EC4vCeJswIBJlO3RqE-wsE72Vt3wAceJ_LzqKvbDtBSY";
        let dig_w = b"EDAyl33W9ja_wLX85UrzRnL4KNzlsIKIA7CrD04nVX1w";
        let dig_x = b"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o";
        let dig_y = b"EFrq74_Q11S2vHx1gpK_46Ik5Q7Yy9K1zZ5BavqGDKnk";

        let dig_c = b"EG5RimdY_OWoreR-Z-Q5G81-I4tjASJCaP_MqkBbtM2w";

        // Test basic key-value operations
        assert_eq!(lmdber.get_val(&db, &key_a0)?, None);
        assert_eq!(lmdber.del_val(&db, &key_a0)?, false);
        assert_eq!(lmdber.put_val(&db, &key_a0, dig_a)?, true);
        assert_eq!(lmdber.get_val(&db, &key_a0)?, Some(dig_a.to_vec()));
        assert_eq!(lmdber.put_val(&db, &key_a0, dig_a)?, false);
        assert_eq!(lmdber.set_val(&db, &key_a0, dig_a)?, true);
        assert_eq!(lmdber.get_val(&db, &key_a0)?, Some(dig_a.to_vec()));
        assert_eq!(lmdber.get_on_val(&db, pre_a, 0, None)?, Some(dig_a.to_vec()));
        assert_eq!(lmdber.del_val(&db, &key_a0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_a0)?, None);
        assert_eq!(lmdber.get_on_val(&db, pre_a, 0, None)?, None);

        // Test ordinal-numbered key-value operations
        assert_eq!(lmdber.put_on_val(&db, pre_a, 0, dig_a, None)?, true);
        assert_eq!(lmdber.get_on_val(&db, pre_a, 0, None)?, Some(dig_a.to_vec()));
        assert_eq!(lmdber.put_on_val(&db, pre_a, 0, dig_a, None)?, false);
        assert_eq!(lmdber.set_on_val(&db, pre_a, Some(0), dig_a, None)?, true);
        assert_eq!(lmdber.get_on_val(&db, pre_a, 0, None)?, Some(dig_a.to_vec()));
        assert_eq!(lmdber.del_on_val(&db, pre_a, 0, None)?, true);
        assert_eq!(lmdber.get_on_val(&db, pre_a, 0, None)?, None);

        // Test append_on_val
        // Empty database
        assert_eq!(lmdber.get_val(&db, &key_b0)?, None);
        let on = lmdber.append_on_val(&db, pre_b, dig_u, Some(sep))?;
        assert_eq!(on, 0);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, Some(dig_u.to_vec()));
        assert_eq!(lmdber.del_val(&db, &key_b0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, None);

        // Earlier pre in database only
        assert_eq!(lmdber.put_val(&db, &key_a0, dig_a)?, true);
        let on = lmdber.append_on_val(&db, pre_b, dig_u, Some(sep))?;
        assert_eq!(on, 0);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, Some(dig_u.to_vec()));
        assert_eq!(lmdber.del_val(&db, &key_b0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, None);

        // Earlier and later pre in db but not same pre
        assert_eq!(lmdber.get_val(&db, &key_a0)?, Some(dig_a.to_vec()));
        assert_eq!(lmdber.put_val(&db, &key_c0, dig_c)?, true);
        let on = lmdber.append_on_val(&db, pre_b, dig_u, Some(sep))?;
        assert_eq!(on, 0);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, Some(dig_u.to_vec()));
        assert_eq!(lmdber.del_val(&db, &key_b0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, None);

        // Later pre only
        assert_eq!(lmdber.del_val(&db, &key_a0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_a0)?, None);
        assert_eq!(lmdber.get_val(&db, &key_c0)?, Some(dig_c.to_vec()));
        assert_eq!(lmdber.len(&db)?, 1);
        let on = lmdber.append_on_val(&db, pre_b, dig_u, Some(sep))?;
        assert_eq!(on, 0);
        assert_eq!(lmdber.len(&db)?, 2);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, Some(dig_u.to_vec()));
        assert_eq!(lmdber.del_val(&db, &key_b0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, None);
        let on = lmdber.append_on_val(&db, pre_b, dig_u, Some(sep))?;
        assert_eq!(on, 0);
        assert_eq!(lmdber.get_val(&db, &key_b0)?, Some(dig_u.to_vec()));

        // Earlier pre and later pre and earlier entry for same pre
        assert_eq!(lmdber.put_val(&db, &key_a0, dig_a)?, true);
        assert_eq!(lmdber.len(&db)?, 3);
        let on = lmdber.append_on_val(&db, pre_b, dig_v, Some(sep))?;
        assert_eq!(on, 1);
        assert_eq!(lmdber.len(&db)?, 4);
        assert_eq!(lmdber.get_val(&db, &key_b1)?, Some(dig_v.to_vec()));
        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(pre_b), None, Some(sep), |ckey, cn, cval| {
            let key = on_key(ckey, cn, Some(sep));
            items.push((key, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items.len(), 2);

        // Earlier entry for same pre but only same pre
        assert_eq!(lmdber.del_val(&db, &key_a0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_a0)?, None);
        assert_eq!(lmdber.del_val(&db, &key_c0)?, true);
        assert_eq!(lmdber.get_val(&db, &key_c0)?, None);
        assert_eq!(lmdber.len(&db)?, 2);

        // Add more values for pre_b
        assert_eq!(lmdber.cnt_on_vals(&db, Some(pre_b), None, Some(sep))?, 2);
        let on = lmdber.append_on_val(&db, pre_b, dig_w, None)?;
        assert_eq!(on, 2);
        assert_eq!(lmdber.get_val(&db, &key_b2)?, Some(dig_w.to_vec()));

        let on = lmdber.append_on_val(&db, pre_b, dig_x, Some(sep))?;
        assert_eq!(on, 3);
        assert_eq!(lmdber.get_val(&db, &key_b3)?, Some(dig_x.to_vec()));

        let on = lmdber.append_on_val(&db, pre_b, dig_y, Some(sep))?;
        assert_eq!(on, 4);
        assert_eq!(lmdber.get_val(&db, &key_b4)?, Some(dig_y.to_vec()));

        assert_eq!(lmdber.append_on_val(&db, pre_d, dig_y, Some(sep))?, 0);

        // Test cnt_on_vals
        assert_eq!(lmdber.cnt_on_vals(&db, Some(pre_b), None, None)?, 5);
        assert_eq!(lmdber.cnt_on_vals(&db, Some(&[]), None, None)?, 6);  // all keys
        assert_eq!(lmdber.cnt_on_vals(&db, None, None, None)?, 6);  // all keys

        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(pre_b), None, Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items, vec![
            (pre_b.to_vec(), 0, dig_u.to_vec()),
            (pre_b.to_vec(), 1, dig_v.to_vec()),
            (pre_b.to_vec(), 2, dig_w.to_vec()),
            (pre_b.to_vec(), 3, dig_x.to_vec()),
            (pre_b.to_vec(), 4, dig_y.to_vec())
        ]);

        // // Resume replay pre_b events at on = 3
        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(pre_b), Some(3), Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items, vec![
            (pre_b.to_vec(), 3, dig_x.to_vec()),
            (pre_b.to_vec(), 4, dig_y.to_vec())
        ]);

        // // Resume replay pre_b events at on = 5
        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(pre_b), Some(5), Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items, vec![]);

        // Replay all events in database with pre events before and after
        assert_eq!(lmdber.put_val(&db, &key_a0, dig_a)?, true);
        assert_eq!(lmdber.put_val(&db, &key_c0, dig_c)?, true);

        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(&[]), None, Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;

        assert_eq!(items, vec![
            (pre_a.to_vec(), 0, dig_a.to_vec()),
            (pre_d.to_vec(), 0, dig_y.to_vec()),
            (pre_b.to_vec(), 0, dig_u.to_vec()),
            (pre_b.to_vec(), 1, dig_v.to_vec()),
            (pre_b.to_vec(), 2, dig_w.to_vec()),
            (pre_b.to_vec(), 3, dig_x.to_vec()),
            (pre_b.to_vec(), 4, dig_y.to_vec()),
            (pre_c.to_vec(), 0, dig_c.to_vec())
        ]);

        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, None, None, Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items, vec![
            (pre_a.to_vec(), 0, dig_a.to_vec()),
            (pre_d.to_vec(), 0, dig_y.to_vec()),
            (pre_b.to_vec(), 0, dig_u.to_vec()),
            (pre_b.to_vec(), 1, dig_v.to_vec()),
            (pre_b.to_vec(), 2, dig_w.to_vec()),
            (pre_b.to_vec(), 3, dig_x.to_vec()),
            (pre_b.to_vec(), 4, dig_y.to_vec()),
            (pre_c.to_vec(), 0, dig_c.to_vec())
        ]);

        // Resume replay all starting at pre_b on=2
        let (top, on) = split_on_key(&key_b2, Some(*b"."))?;
        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(&top), Some(on), Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items, vec![
            (top.clone(), 2, dig_w.to_vec()),
            (top.clone(), 3, dig_x.to_vec()),
            (top.clone(), 4, dig_y.to_vec())
        ]);

        // Resume replay all starting at pre_c on=1
        let mut items = Vec::new();
        lmdber.get_on_item_iter(&db, Some(pre_c), Some(1), Some(sep), |ckey, cn, cval| {
            items.push((ckey, cn, cval));
            Ok(true)
        })?;
        assert_eq!(items, vec![]);

        let mut items = Vec::new();
        lmdber.get_on_val_iter(&db, Some(pre_b), None, Some(sep), |cval| {
            items.push(cval);
            Ok(true)
        })?;
        assert_eq!(items, vec![
            dig_u.to_vec(),
            dig_v.to_vec(),
            dig_w.to_vec(),
            dig_x.to_vec(),
            dig_y.to_vec()
        ]);

        // // Resume replay pre_b events at on = 3
        let mut items = Vec::new();
        lmdber.get_on_val_iter(&db, Some(pre_b), Some(3), Some(sep), |cval| {
            items.push(cval);
            Ok(true)
        })?;
        assert_eq!(items, vec![
            dig_x.to_vec(),
            dig_y.to_vec()
        ]);
        
        Ok(())
    }

    #[test]
    fn test_basic_io_set() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key = b"test_key";
        let vals1: [&[u8]; 3] = [b"value1", b"value2", b"value3"];
        let vals2: [&[u8]; 3] = [b"value3", b"value4", b"value5"];

        // Put the first set of values
        lmdber.put_io_set_vals(&db, key, &vals1, None)?;

        // Get the values
        let result1 = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(result1.len(), 3);
        assert_eq!(result1[0], b"value1".to_vec());
        assert_eq!(result1[1], b"value2".to_vec());
        assert_eq!(result1[2], b"value3".to_vec());

        // Put another set of values, some overlapping
        lmdber.put_io_set_vals(&db, key, &vals2, None)?;

        // Get the values again
        let result2 = lmdber.get_io_set_vals(&db, key, None, None)?;

        // Should have 5 values with no duplicates, in insertion order
        assert_eq!(result2.len(), 5);
        assert_eq!(result2[0], b"value1".to_vec());
        assert_eq!(result2[1], b"value2".to_vec());
        assert_eq!(result2[2], b"value3".to_vec());
        assert_eq!(result2[3], b"value4".to_vec());
        assert_eq!(result2[4], b"value5".to_vec());

        // Test starting from a specific ordinal
        let result3 = lmdber.get_io_set_vals(&db, key, Some(2), None)?;
        assert_eq!(result3.len(), 3);
        assert_eq!(result3[0], b"value3".to_vec());
        assert_eq!(result3[1], b"value4".to_vec());
        assert_eq!(result3[2], b"value5".to_vec());

        Ok(())

    }

    #[test]
    fn test_add_io_set_val() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key = b"test_key";
        let val1 = b"value1";
        let val2 = b"value2";

        // Add the first value
        let result1 = lmdber.add_io_set_val(&db, key, val1, None)?;
        assert!(result1, "First add should return true");

        // Add the same value again
        let result2 = lmdber.add_io_set_val(&db, key, val1, None)?;
        assert!(!result2, "Adding same value should return false");

        // Add a different value
        let result3 = lmdber.add_io_set_val(&db, key, val2, None)?;
        assert!(result3, "Adding new value should return true");

        // Verify the values were added in the correct order
        let values = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], val1.to_vec());
        assert_eq!(values[1], val2.to_vec());

        Ok(())
    }

    #[test]
    fn test_del_io_set_vals() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key1 = b"test_key1";
        let key2 = b"test_key2";
        let vals: [&[u8]; 3] = [b"value1", b"value2", b"value3"];

        // Add values to key1
        lmdber.put_io_set_vals(&db, key1, &vals, None)?;

        // Add values to key2
        lmdber.put_io_set_vals(&db, key2, &vals, None)?;

        // Verify values were added
        let values1 = lmdber.get_io_set_vals(&db, key1, None, None)?;
        let values2 = lmdber.get_io_set_vals(&db, key2, None, None)?;
        assert_eq!(values1.len(), 3);
        assert_eq!(values2.len(), 3);

        // Delete values for key1
        let result1 = lmdber.del_io_set_vals(&db, key1, None)?;
        assert!(result1, "Should return true when values are deleted");

        // Verify key1 values are gone
        let values1_after = lmdber.get_io_set_vals(&db, key1, None, None)?;
        assert_eq!(values1_after.len(), 0, "All values should be deleted");

        // Verify key2 values still exist
        let values2_after = lmdber.get_io_set_vals(&db, key2, None, None)?;
        assert_eq!(values2_after.len(), 3, "Key2 values should be untouched");

        // Try to delete values for a key that doesn't exist
        let result2 = lmdber.del_io_set_vals(&db, b"nonexistent_key", None)?;
        assert!(!result2, "Should return false when no values exist");

        Ok(())
    }

    #[test]
    fn test_del_io_set_val() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key = b"test_key";
        let val1 = b"value1";
        let val2 = b"value2";
        let val3 = b"value3";

        // Add values to key
        let vals: [&[u8]; 3] = [val1, val2, val3];
        lmdber.put_io_set_vals(&db, key, &vals, None)?;

        // Verify values were added
        let values = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(values.len(), 3);

        // Delete the second value
        let result1 = lmdber.del_io_set_val(&db, key, val2, None)?;
        assert!(result1, "Should return true when value is deleted");

        // Verify value was deleted
        let values_after = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(values_after.len(), 2);
        assert_eq!(values_after[0], val1.to_vec());
        assert_eq!(values_after[1], val3.to_vec());

        // Try to delete a value that doesn't exist
        let result2 = lmdber.del_io_set_val(&db, key, b"nonexistent_value", None)?;
        assert!(!result2, "Should return false when value doesn't exist");

        // Try to delete from a key that doesn't exist
        let result3 = lmdber.del_io_set_val(&db, b"nonexistent_key", val1, None)?;
        assert!(!result3, "Should return false when key doesn't exist");

        Ok(())
    }

    #[test]
    fn test_set_io_set_vals() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key = b"test_key";
        let vals1 = [b"value1", b"value2", b"value3"];

        // Set values for key
        let result1 = lmdber.set_io_set_vals(&db, key, &vals1, None)?;
        assert!(result1, "Should return true when values are set");

        // Verify values were added
        let values1 = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(values1.len(), 3);
        assert_eq!(values1[0], b"value1".to_vec());
        assert_eq!(values1[1], b"value2".to_vec());
        assert_eq!(values1[2], b"value3".to_vec());

        // Replace with a new set of values, including duplicates
        let vals2 = [b"value4", b"value5", b"value4"]; // Note the duplicate
        let result2 = lmdber.set_io_set_vals(&db, key, &vals2, None)?;
        assert!(result2, "Should return true when values are set");

        // Verify original values were removed and new unique values added
        let values2 = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(values2.len(), 2); // Should deduplicate
        assert_eq!(values2[0], b"value4".to_vec());
        assert_eq!(values2[1], b"value5".to_vec());

        // Set with empty array
        let empty: [&[u8]; 0] = [];
        let result3 = lmdber.set_io_set_vals(&db, key, &empty, None)?;
        assert!(result3, "Should return true even with empty array");

        // Verify all values were removed
        let values3 = lmdber.get_io_set_vals(&db, key, None, None)?;
        assert_eq!(values3.len(), 0, "All values should be removed");

        Ok(())
    }

    #[test]
    fn test_cnt_io_set_vals() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key1 = b"test_key1";
        let key2 = b"test_key2";
        let vals1: [&[u8]; 3] = [b"value1", b"value2", b"value3"];
        let vals2: [&[u8]; 2] = [b"value4", b"value5"];

        // Count values for non-existent key
        let count1 = lmdber.cnt_io_set_vals(&db, key1, None)?;
        assert_eq!(count1, 0, "Count for non-existent key should be 0");

        // Add values to key1
        lmdber.put_io_set_vals(&db, key1, &vals1, None)?;

        // Count values for key1
        let count2 = lmdber.cnt_io_set_vals(&db, key1, None)?;
        assert_eq!(count2, 3, "Count should match number of values added");

        // Add values to key2
        lmdber.put_io_set_vals(&db, key2, &vals2, None)?;

        // Count values for key2
        let count3 = lmdber.cnt_io_set_vals(&db, key2, None)?;
        assert_eq!(count3, 2, "Count should match number of values added");

        // Delete a value from key1
        lmdber.del_io_set_val(&db, key1, b"value2", None)?;

        // Count values for key1 again
        let count4 = lmdber.cnt_io_set_vals(&db, key1, None)?;
        assert_eq!(count4, 2, "Count should be updated after deletion");

        // Delete all values for key2
        lmdber.del_io_set_vals(&db, key2, None)?;

        // Count values for key2 again
        let count5 = lmdber.cnt_io_set_vals(&db, key2, None)?;
        assert_eq!(count5, 0, "Count should be 0 after deleting all values");

        Ok(())
    }

    #[test]
    fn test_get_io_set_vals_iter() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key = b"test_key";
        let vals: [&[u8]; 5] = [b"value1", b"value2", b"value3", b"value4", b"value5"];

        // Add values to key
        lmdber.put_io_set_vals(&db, key, &vals, None)?;

        // Test full iteration
        let mut collected_vals = Vec::new();
        lmdber.get_io_set_vals_iter(&db, key, None, None, |val| {
            collected_vals.push(val.to_vec());
            Ok(true) // Continue iteration
        })?;

        assert_eq!(collected_vals.len(), 5);
        assert_eq!(collected_vals[0], b"value1".to_vec());
        assert_eq!(collected_vals[4], b"value5".to_vec());

        // Test starting from a specific ordinal
        let mut collected_vals2 = Vec::new();
        lmdber.get_io_set_vals_iter(&db, key, Some(2), None, |val| {
            collected_vals2.push(val.to_vec());
            Ok(true) // Continue iteration
        })?;

        assert_eq!(collected_vals2.len(), 3); // Should only get values 3, 4, 5
        assert_eq!(collected_vals2[0], b"value3".to_vec());
        assert_eq!(collected_vals2[2], b"value5".to_vec());

        // Test early termination
        let mut collected_vals3 = Vec::new();
        lmdber.get_io_set_vals_iter(&db, key, None, None, |val| {
            collected_vals3.push(val.to_vec());
            // Stop after collecting 2 values
            Ok(collected_vals3.len() < 2)
        })?;

        assert_eq!(collected_vals3.len(), 2); // Should only get values 1, 2
        assert_eq!(collected_vals3[0], b"value1".to_vec());
        assert_eq!(collected_vals3[1], b"value2".to_vec());

        // Test non-existent key
        let mut non_existent_vals = Vec::new();
        lmdber.get_io_set_vals_iter(&db, b"non_existent_key", None, None, |val| {
            non_existent_vals.push(val.to_vec());
            Ok(true)
        })?;

        assert_eq!(non_existent_vals.len(), 0); // Should not collect any values

        Ok(())
    }

    #[test]
    fn test_get_io_set_val_last() -> Result<(), DBError> {
        // Create a temporary database
        let lmdber = LMDBer::builder().temp(true).build()?;
        let db = lmdber.create_database(Some("test_io_set"), Some(false))?;

        // Test key and values
        let key1 = b"test_key1";
        let key2 = b"test_key2";

        // Test with empty database
        let result1 = lmdber.get_io_set_val_last(&db, key1, None)?;
        assert_eq!(result1, None, "Should return None for non-existent key");

        // Add a single value to key1
        let val1 = b"value1";
        lmdber.add_io_set_val(&db, key1, val1, None)?;

        // Check last value for key1
        let result2 = lmdber.get_io_set_val_last(&db, key1, None)?;
        assert_eq!(result2, Some(val1.to_vec()), "Should return the only value");

        // Add more values to key1
        let val2 = b"value2";
        let val3 = b"value3";
        lmdber.add_io_set_val(&db, key1, val2, None)?;
        lmdber.add_io_set_val(&db, key1, val3, None)?;

        // Check last value for key1
        let result3 = lmdber.get_io_set_val_last(&db, key1, None)?;
        assert_eq!(result3, Some(val3.to_vec()), "Should return the last added value");

        // Add values to key2, which lexicographically follows key1
        let val4 = b"value4";
        lmdber.add_io_set_val(&db, key2, val4, None)?;

        // Check last value for key1 again (should be unaffected by key2)
        let result4 = lmdber.get_io_set_val_last(&db, key1, None)?;
        assert_eq!(result4, Some(val3.to_vec()), "Should still return the last value for key1");

        // Check last value for key2
        let result5 = lmdber.get_io_set_val_last(&db, key2, None)?;
        assert_eq!(result5, Some(val4.to_vec()), "Should return the only value for key2");

        // Add values to a key that lexicographically precedes key1
        let key0 = b"test_key0";
        let val5 = b"value5";
        lmdber.add_io_set_val(&db, key0, val5, None)?;

        // Check last values for all keys
        let result6 = lmdber.get_io_set_val_last(&db, key0, None)?;
        assert_eq!(result6, Some(val5.to_vec()), "Should return the only value for key0");

        let result7 = lmdber.get_io_set_val_last(&db, key1, None)?;
        assert_eq!(result7, Some(val3.to_vec()), "Should still return the last value for key1");

        // Delete all values for key1
        lmdber.del_io_set_vals(&db, key1, None)?;

        // Check last value for key1 after deletion
        let result8 = lmdber.get_io_set_val_last(&db, key1, None)?;
        assert_eq!(result8, None, "Should return None after all values are deleted");

        Ok(())
    }

    #[test]
    fn test_io_set_methods() -> Result<(), DBError> {

        Ok(())
    }
}
