# TODO Checklist for Rust KERI Implementation

Below is a checklist to track progress against the **multi-iteration** plan. Check off items as you complete them.

---

## **Phase 1: CESR Primitives**

- [ ] **1.1**: Initialize a new Cargo project (`cargo new keri_rust`)
    - [ ] Add dependencies in `Cargo.toml`:
        - `tokio`
        - `tracing`
        - `thiserror`
        - `serde`, `serde_json`
        - `sodiumoxide`
    - [ ] Create a basic `main.rs` that prints "Hello KERI!"
    - [ ] Confirm project compiles and runs.

- [ ] **1.2**: Add basic project structure
    - [ ] Create `lib.rs` with `mod errors;`, `mod cesr;`, etc.
    - [ ] Create corresponding `errors.rs` and `cesr.rs` files.

- [ ] **1.3**: Implement error types
    - [ ] In `errors.rs`, define an `Error` enum using `thiserror`.
    - [ ] Include variants for:
        - Serialization
        - Parsing
        - Cryptographic issues
        - Generic "Other"
    - [ ] Re-export `Error` from `lib.rs`.

- [ ] **1.4**: Define CESR data structures
    - [ ] In `cesr.rs`, create structs like:
        - `Prefix` (e.g., `pub value: String`)
        - `Signature`
        - `KeyPair`
    - [ ] Derive `Debug, Clone, PartialEq`.
    - [ ] Add minimal doc comments for each.

- [ ] **1.5**: Implement CESR serialization/deserialization
    - [ ] `serialize_cesr` & `deserialize_cesr` functions for each struct.
    - [ ] Round-trip test (serialize → deserialize → compare).

- [ ] **1.6**: Add unit tests for CESR
    - [ ] Replicate KERIpy test data if available.
    - [ ] Validate that output matches KERIpy references.

---

## **Phase 2: CESR Parser**

- [ ] **2.1**: Create a `parser.rs` module
    - [ ] Add `mod parser;` to `lib.rs`.
    - [ ] Define a `Parser` struct with a placeholder `parse_cesr_data(&self, data: &[u8])`.

- [ ] **2.2**: Integrate `serde` for parsing
    - [ ] Convert byte slices to JSON strings, parse into Rust structs (`Prefix`, etc.).
    - [ ] Implement error handling for malformed input.

- [ ] **2.3**: Expand parser logic
    - [ ] Handle arrays of prefixes or other CESR objects.
    - [ ] Add more nuanced parsing rules if needed.

- [ ] **2.4**: Add parser tests
    - [ ] Create `tests/parser_tests.rs`.
    - [ ] Validate JSON input → `Prefix` structs.
    - [ ] Test both valid and invalid input.

---

## **Phase 3: Kevery (Event Validation & Processing)**

- [ ] **3.1**: Define validation traits & interfaces
    - [ ] Create `validator.rs` with `Validator` trait:
        - `fn validate_prefix(&self, prefix: &Prefix) -> Result<(), Error>;`
    - [ ] Implement a `BasicValidator`.

- [ ] **3.2**: Integrate cryptographic checks
    - [ ] Initialize libsodium in `main.rs` or `lib.rs`.
    - [ ] For now, stub out real Ed25519 checks (or partially implement them).

- [ ] **3.3**: Establish storage abstraction
    - [ ] Create `storage.rs` with a `Storage` trait (async).
    - [ ] Outline typical methods (`get_prefix`, `put_prefix`, etc.).

- [ ] **3.4**: Implement `Kevery` struct
    - [ ] Accept a `Validator` and a `Storage` reference.
    - [ ] `process_prefix(&mut self, prefix: Prefix) -> Result<(), Error>` that:
        - Validates the prefix.
        - On success, stores in DB.
        - On failure, escrows it.

- [ ] **3.5**: Implement escrow mechanism
    - [ ] Keep an in-memory list/vector of invalid prefixes.
    - [ ] Add `retry_escrowed_events` method.

- [ ] **3.6**: Add unit tests for Kevery
    - [ ] In `tests/kevery_tests.rs`, ensure:
        - Valid events get stored.
        - Invalid events go to escrow.
        - Retrying eventually passes or fails.

---

## **Phase 4: Hab & Habery**

- [ ] **4.1**: Create `hab.rs` & `habery.rs`
    - [ ] `Hab` struct for a single prefix + key management.
    - [ ] `Habery` struct managing multiple `Hab` via `RwLock<HashMap<...>>`.

- [ ] **4.2**: Manage concurrency in `Habery`
    - [ ] Implement methods for creating/deleting/looking up `Hab`.
    - [ ] Ensure thread-safe operations.

- [ ] **4.3**: Pluggable key management
    - [ ] A `KeyManager` trait with methods like `generate_keypair`, `sign`, `verify`.
    - [ ] Default software-based implementation using libsodium.

- [ ] **4.4**: Add caching (LRU for key states)
    - [ ] Integrate an LRU cache crate (`lru`) if needed.
    - [ ] Connect it to `Hab` or `Habery`.

- [ ] **4.5**: Import/export
    - [ ] Implement `export_events(&self) -> Vec<u8>` (CESR event stream).
    - [ ] Implement `import_events(&mut self, data: &[u8]) -> Result<(), Error>` for re-validation.

- [ ] **4.6**: Unit tests for `Hab` & `Habery`
    - [ ] Ensure multiple `Hab` instances can be created/managed.
    - [ ] Test key generation/sign/verify.
    - [ ] Test import/export flows.

---

## **Phase 5: Testing, Docs & Finalization**

- [ ] **5.1**: Complete unit test coverage
    - [ ] Verify parity with KERIpy’s coverage/structure.
    - [ ] Test all error paths and edge cases.

- [ ] **5.2**: Add Rustdoc comments
    - [ ] `///` for all public structs, traits, and methods.
    - [ ] Document usage and expected behavior.

- [ ] **5.3**: Provide usage examples
    - [ ] In `examples/` or inline doc tests.
    - [ ] Show how to create `Habery`, generate events, validate, store, export, import.

- [ ] **5.4**: Optional integration tests
    - [ ] Validate that output from Rust implementation is compatible with KERIpy.

- [ ] **5.5**: Confirm no unused/orphaned code
    - [ ] Remove or integrate any placeholders left behind.

---

## **Done!**
Once all items above are checked, you’ll have a **complete** Rust KERI implementation that:
1. Follows KERIpy’s modular design,
2. Ensures functional compatibility,
3. Adheres to Rust idioms (async-first, trait-based, structured error handling),
4. Includes robust test coverage.

Keep this `todo.md` updated as you progress. Good luck!