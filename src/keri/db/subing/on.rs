use crate::keri::db::dbing::LMDBer;
use crate::keri::db::subing::{OnSuberBase, Suber};
use crate::keri::db::subing::{SuberError, Utf8Codec, ValueCodec};
use std::sync::Arc;

pub struct OnSuber<'db, C: ValueCodec = Utf8Codec> {
    pub base: Suber<'db, C>,
    pub on_base: OnSuberBase<'db, C>,
}

impl<'db, C: ValueCodec> OnSuber<'db, C> {
    pub fn new(
        db: Arc<&'db LMDBer>,
        subkey: &str,
        sep: Option<u8>,
        verify: bool,
    ) -> Result<Self, SuberError> {
        let base = Suber::new(db.clone(), subkey, sep, verify)?;
        let on_base = OnSuberBase::new(db, subkey, sep, verify, Some(false))?;

        Ok(Self { base, on_base })
    }

    // === Methods from Suber ===

    pub fn put<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        self.base.put(keys, val)
    }

    pub fn pin<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<bool, SuberError> {
        self.base.pin(keys, val)
    }

    pub fn get<K: AsRef<[u8]>, V: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
    ) -> Result<Option<V>, SuberError> {
        self.base.get(keys)
    }

    pub fn rem<K: AsRef<[u8]>>(&self, keys: &[K]) -> Result<bool, SuberError> {
        self.base.rem(keys)
    }

    pub fn trim<K: AsRef<[u8]>>(&self, keys: &[K], topive: bool) -> Result<bool, SuberError> {
        self.base.trim(keys, topive)
    }

    pub fn get_full_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.get_full_item_iter(keys, topive)
    }

    pub fn get_item_iter<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        topive: bool,
    ) -> Result<Vec<(Vec<Vec<u8>>, Vec<u8>)>, SuberError> {
        self.base.get_item_iter(keys, topive)
    }

    pub fn cnt_all(&self) -> Result<usize, SuberError> {
        self.base.cnt_all()
    }

    // === Methods from OnSuberBase ===

    pub fn is_dupsort(&self) -> bool {
        self.on_base.is_dupsort()
    }

    pub fn put_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        self.on_base.put_on(keys, on, val)
    }

    pub fn pin_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
        val: &V,
    ) -> Result<bool, SuberError> {
        self.on_base.pin_on(keys, on, val)
    }

    pub fn append_on<K: AsRef<[u8]>, V: ?Sized + Clone + Into<Vec<u8>>>(
        &self,
        keys: &[K],
        val: &V,
    ) -> Result<u64, SuberError> {
        self.on_base.append_on(keys, val)
    }

    pub fn get_on<K: AsRef<[u8]>, R: TryFrom<Vec<u8>>>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Option<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.on_base.get_on(keys, on)
    }

    pub fn rem_on<K: AsRef<[u8]>>(&self, keys: &[K], on: u32) -> Result<bool, SuberError> {
        self.on_base.rem_on(keys, on)
    }

    pub fn cnt_on<K: AsRef<[u8]>>(&self, keys: &[K], on: u32) -> Result<usize, SuberError> {
        self.on_base.cnt_on(keys, on)
    }

    pub fn get_on_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<R>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.on_base.get_on_iter(keys, on)
    }

    pub fn get_on_item_iter<K: AsRef<[u8]>, R: TryFrom<Vec<u8>> + 'static>(
        &self,
        keys: &[K],
        on: u32,
    ) -> Result<Vec<(Vec<Vec<u8>>, u64, R)>, SuberError>
    where
        <R as TryFrom<Vec<u8>>>::Error: std::fmt::Debug,
    {
        self.on_base.get_on_item_iter(keys, on)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::db::dbing::LMDBer;
    use std::sync::Arc;

    #[test]
    fn test_on_suber() -> Result<(), SuberError> {
        // Create a temporary database
        let db = LMDBer::builder()
            .temp(true)
            .name("test")
            .build()
            .map_err(SuberError::DBError)?;

        assert_eq!(db.name(), "test");
        assert!(db.opened());

        let db_ref = Arc::new(&db);

        // Create OnSuber instance
        let onsuber = OnSuber::<Utf8Codec>::new(db_ref, "bags.", None, false)?;

        // Verify not dupsort (matches Python test)
        assert!(!onsuber.is_dupsort());

        // Test values
        let w = "Blue dog";
        let x = "Green tree";
        let y = "Red apple";
        let z = "White snow";

        // Test append_on
        assert_eq!(onsuber.append_on(&["a"], &w)?, 0);
        assert_eq!(onsuber.append_on(&["a"], &x)?, 1);
        assert_eq!(onsuber.append_on(&["a"], &y)?, 2);
        assert_eq!(onsuber.append_on(&["a"], &z)?, 3);

        // Test cnt_on
        assert_eq!(onsuber.cnt_on(&["a"], 0)?, 4);
        assert_eq!(onsuber.cnt_on(&["a"], 2)?, 2);
        assert_eq!(onsuber.cnt_on(&["a"], 4)?, 0);

        // Test get_item_iter
        let items: Vec<(Vec<Vec<u8>>, Vec<u8>)> = onsuber.get_item_iter(&[] as &[&str], true)?;

        // Convert to strings for easier assertions
        let items_as_strings: Vec<(Vec<String>, String)> = items
            .into_iter()
            .map(|(keys_bytes, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(items_as_strings.len(), 4);
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Blue dog".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "Green tree".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000002".to_string()
            ],
            "Red apple".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000003".to_string()
            ],
            "White snow".to_string()
        )));

        // Test get_on_item_iter
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> =
            onsuber.get_on_item_iter::<&str, Vec<u8>>(&[] as &[&str], 0)?;

        // Convert to strings for easier assertions
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 4);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            1,
            "Green tree".to_string()
        )));
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            3,
            "White snow".to_string()
        )));

        // Test get_on_item_iter with specific key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["a"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 4);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            1,
            "Green tree".to_string()
        )));
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            3,
            "White snow".to_string()
        )));

        // Test get_on_item_iter with specific on index
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["a"], 2)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["a".to_string()],
            3,
            "White snow".to_string()
        )));

        // Test get_on_iter - no args
        let on_vals: Vec<Vec<u8>> = onsuber.get_on_iter::<&str, Vec<u8>>(&[] as &[&str], 0)?;

        // Convert to strings
        let on_vals_as_strings: Vec<String> = on_vals
            .into_iter()
            .map(|val| String::from_utf8(val).unwrap())
            .collect();

        assert_eq!(on_vals_as_strings.len(), 4);
        assert!(on_vals_as_strings.contains(&"Blue dog".to_string()));
        assert!(on_vals_as_strings.contains(&"Green tree".to_string()));
        assert!(on_vals_as_strings.contains(&"Red apple".to_string()));
        assert!(on_vals_as_strings.contains(&"White snow".to_string()));

        // Test get_on_iter with specific key
        let on_vals: Vec<Vec<u8>> = onsuber.get_on_iter(&["a"], 0)?;

        // Convert to strings
        let on_vals_as_strings: Vec<String> = on_vals
            .into_iter()
            .map(|val| String::from_utf8(val).unwrap())
            .collect();

        assert_eq!(on_vals_as_strings.len(), 4);
        assert!(on_vals_as_strings.contains(&"Blue dog".to_string()));
        assert!(on_vals_as_strings.contains(&"Green tree".to_string()));
        assert!(on_vals_as_strings.contains(&"Red apple".to_string()));
        assert!(on_vals_as_strings.contains(&"White snow".to_string()));

        // Test get_on_iter with specific on index
        let on_vals: Vec<Vec<u8>> = onsuber.get_on_iter(&["a"], 2)?;

        // Convert to strings
        let on_vals_as_strings: Vec<String> = on_vals
            .into_iter()
            .map(|val| String::from_utf8(val).unwrap())
            .collect();

        assert_eq!(on_vals_as_strings.len(), 2);
        assert!(on_vals_as_strings.contains(&"Red apple".to_string()));
        assert!(on_vals_as_strings.contains(&"White snow".to_string()));

        // Test append for additional keys
        assert_eq!(onsuber.append_on(&["b"], &w)?, 0);
        assert_eq!(onsuber.append_on(&["b"], &x)?, 1);
        assert_eq!(onsuber.append_on(&["bc"], &y)?, 0);
        assert_eq!(onsuber.append_on(&["ac"], &z)?, 0);

        // Test counts
        assert_eq!(onsuber.cnt_on(&["b"], 0)?, 2);
        assert_eq!(onsuber.cnt_on(&["ac"], 2)?, 0);
        assert_eq!(onsuber.cnt_on(&[""], 0)?, 8);

        // Test get_item_iter for all items
        let items = onsuber.get_item_iter::<Vec<u8>>(&[], true)?;

        // Convert to strings for easier assertions
        let items_as_strings: Vec<(Vec<String>, String)> = items
            .into_iter()
            .map(|(keys_bytes, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(items_as_strings.len(), 8);
        // Check all the key-value pairs we expect
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Blue dog".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "Green tree".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000002".to_string()
            ],
            "Red apple".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "a".to_string(),
                "00000000000000000000000000000003".to_string()
            ],
            "White snow".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "ac".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "White snow".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "b".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Blue dog".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "b".to_string(),
                "00000000000000000000000000000001".to_string()
            ],
            "Green tree".to_string()
        )));
        assert!(items_as_strings.contains(&(
            vec![
                "bc".to_string(),
                "00000000000000000000000000000000".to_string()
            ],
            "Red apple".to_string()
        )));

        // Test get_on_item_iter with specific key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["b"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["b".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["b".to_string()],
            1,
            "Green tree".to_string()
        )));

        // Test get_on_item_iter with tuple key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["b"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["b".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(
            vec!["b".to_string()],
            1,
            "Green tree".to_string()
        )));

        // Test get_on_item_iter with empty key parts
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> =
            onsuber.get_on_item_iter(&["b", ""], 0)?;
        assert_eq!(on_items.len(), 0);

        // Test get_on_item_iter with empty key
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&[""], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 8);
        // Here we'd check all 8 items but for brevity I'll check just the count

        // Test get_on_item_iter with no args
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> =
            onsuber.get_on_item_iter::<&str, Vec<u8>>(&[], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 8);
        // Again, just checking count for brevity

        // Test rem_on
        assert!(onsuber.rem_on(&["a"], 1)?);
        assert!(!onsuber.rem_on(&["a"], 1)?); // Should now return false as already removed
        assert!(onsuber.rem_on(&["a"], 3)?);
        assert!(!onsuber.rem_on(&["a"], 3)?); // Should now return false as already removed

        // Verify count after removal
        assert_eq!(onsuber.cnt_on(&["a"], 0)?, 2);

        // Test get_on_item_iter after removals
        let on_items: Vec<(Vec<Vec<u8>>, u64, Vec<u8>)> = onsuber.get_on_item_iter(&["a"], 0)?;

        // Convert to strings
        let on_items_as_strings: Vec<(Vec<String>, u64, String)> = on_items
            .into_iter()
            .map(|(keys_bytes, idx, val_bytes)| {
                let parsed_keys = keys_bytes
                    .into_iter()
                    .map(|k| String::from_utf8(k).unwrap())
                    .collect();
                (parsed_keys, idx, String::from_utf8(val_bytes).unwrap())
            })
            .collect();

        assert_eq!(on_items_as_strings.len(), 2);
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 0, "Blue dog".to_string())));
        assert!(on_items_as_strings.contains(&(vec!["a".to_string()], 2, "Red apple".to_string())));

        // Test put_on and get_on
        assert!(onsuber.put_on(&["d"], 0, &"moon")?);
        let moon: Option<Vec<u8>> = onsuber.get_on(&["d"], 0)?;
        assert!(moon.is_some());
        assert_eq!(String::from_utf8(moon.unwrap()).unwrap(), "moon");

        // Test put_on with duplicate (should return false)
        assert!(!onsuber.put_on(&["d"], 0, &"moon")?);

        // Test pin_on
        assert!(onsuber.pin_on(&["d"], 0, &"sun")?);
        let sun: Option<Vec<u8>> = onsuber.get_on(&["d"], 0)?;
        assert!(sun.is_some());
        assert_eq!(String::from_utf8(sun.unwrap()).unwrap(), "sun");

        // Test rem_on
        assert!(onsuber.rem_on(&["d"], 0)?);

        // The database should be closed when db goes out of scope
        drop(db);

        Ok(())
    }
}
