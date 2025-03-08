# **Multi-Iteration Development Blueprint (All in Markdown)**

Below is a **step-by-step** plan, broken down into incremental chunks. Each section provides **context** and **action items**. Following that, you’ll find **code-generation prompts**, each enclosed in code tags. The prompts are designed to be run **in order**, ensuring no orphaned code or missing integrations.

---

## **Round 1: High-Level Phases**

1. **Phase 1: CESR Primitives**
    - Create basic data structures for CESR (e.g., common types, encodings).
    - Implement serialization logic for CESR.
    - Provide tests mirroring KERIpy’s CESR tests.

2. **Phase 2: CESR Parser**
    - Develop a parser that processes CESR-encoded data into Rust structures.
    - Validate correctness (e.g., decode properly).
    - Write tests using the same vectors/data as KERIpy.

3. **Phase 3: Kevery**
    - Implement synchronous validation logic.
    - Integrate with the storage abstraction to persist validated events.
    - Implement an escrow for invalid events and a background retry mechanism.

4. **Phase 4: Hab & Habery**
    - Port the class hierarchy from KERIpy into Rust (structs, traits, concurrency, caching).
    - Manage multiple `Hab` instances concurrently with `tokio`.
    - Provide an API for escrow management, import/export, and event replay.

5. **Phase 5: Testing & Documentation**
    - Ensure all unit tests match KERIpy’s coverage.
    - Add Rustdoc, usage examples, and developer guides.
    - Finalize readiness for iterative improvement (CI, benchmarks, etc.).

---

## **Round 2: Breaking Phases into Smaller Steps**

### **Phase 1: CESR Primitives**

1. **Create a New Cargo Project & Add Dependencies**
2. **Define CESR Data Structures**
    - `Prefix`, `Signature`, `KeyPair`, etc.
3. **Implement Basic Serialization/Deserialization**
4. **Integrate Error Handling**
    - Define custom error types with `thiserror`.
5. **Implement Unit Tests**
    - Match KERIpy test vectors where possible.

### **Phase 2: CESR Parser**

1. **Introduce a `Parser` Module**
    - Process raw byte streams into CESR structs.
2. **Integrate With `Serde`**
    - For JSON in/out if needed.
3. **Build Out More Complex Decoding Logic**
4. **Add Unit Tests**
    - Validate parser correctness vs. KERIpy input/output.

### **Phase 3: Kevery**

1. **Define Validation Traits & Interfaces**
2. **Implement Synchronous Event Validation**
    - Leverage cryptographic checks (Ed25519 via libsodium).
3. **Establish Storage Abstraction**
4. **Persist Validated Events to Storage**
    - LMDB-based.
5. **Implement Escrow**
    - Store invalid events, re-check later.
6. **Unit Tests**
    - Cover valid and invalid event flows.

### **Phase 4: Hab & Habery**

1. **Design the Structs** (`Hab`, `Habery`)
2. **Manage Multiple `Hab` Instances**
3. **Implement Key Management**
4. **Add Caching** (LRU)
5. **Import/Export** (CESR event stream)
6. **Unit Tests**
    - Test concurrency, import/export correctness.

### **Phase 5: Testing & Documentation**

1. **Expand Unit Tests for Full Coverage**
2. **Rustdoc Comments**
3. **Usage Examples**
4. **Optional Integration Tests**
    - Verify cross-compatibility with KERIpy.

---

## **Round 3: Finer-Grained, Actionable Steps**

Below is an expanded breakdown of **Phase 1** as an example. Apply similar expansions to other phases as needed.

### **Phase 1: CESR Primitives**

1. **Set Up Project**
    - [1.1] Initialize a new Cargo project (`cargo new`).
    - [1.2] Add fundamental dependencies (`thiserror`, `serde`, `serde_json`, `tracing`, `tokio`, `sodiumoxide`).

2. **Add Basic Project Structure**
    - [1.3] Create a `lib.rs` with a `cesr` module.
    - [1.4] Add `mod errors;`, `mod types;`.

3. **Implement Error Types**
    - [1.5] Create `Error` enum in `errors.rs` using `thiserror`.
    - [1.6] Provide variants for serialization, parsing, crypto, etc.

4. **Define CESR Data Structures**
    - [1.7] In `types.rs`, define `Prefix`, `Signature`, `KeyPair`, etc.
    - [1.8] Mirror KERIpy’s classes and fields.

5. **Implement CESR Serialization**
    - [1.9] `serialize_cesr` / `deserialize_cesr` functions.
    - [1.10] Write round-trip tests for each struct.

6. **Add Unit Tests**
    - [1.11] Use KERIpy’s known test vectors.
    - [1.12] Confirm coverage for multiple examples.

---

# **Prompts for a Code-Generation LLM**

Below is a series of prompts that you can feed into a code-generation LLM (like GitHub Copilot, ChatGPT’s Code Interpreter mode, etc.). Each prompt builds on the results of the previous prompts—be sure to run them in order. When the LLM finishes one prompt, save or commit the resulting code, then move to the next.

	Note: The text and file structures here are suggestions. You may adapt to your project as needed.


### **Prompt #1: Initialize the Project**
```text
Please create a new Rust project named "libkeri" with a Cargo.toml that includes the following dependencies:

- tokio (latest version)
- tracing (latest version)
- thiserror (latest version)
- serde and serde_json (latest)
- sodiumoxide (for libsodium-based crypto)

Set up the project with a basic `lib.rs` file. Also include a `main.rs` that just prints "Hello KERI!" to confirm our setup works.
```

### Prompt #2: Add Basic Modules & Error Handling

```text
Now that we have a basic project structure, please add:

1. A `mod errors;` within `lib.rs`.
2. An `errors.rs` file that defines a custom `Error` enum using `thiserror`, including variants for:
   - Serialization errors
   - Parsing errors
   - Cryptographic errors
   - A generic "Other" variant

Ensure each variant has an appropriate error message. Also re-export `Error` from `lib.rs`.
```

### Architect Prompt for Matter
```text
Can you analyze the Python class structure from coring.py, starting with the class Matter and recommend a design for Rust equivilent of Matter and all its subclasses, using Rust structs and traits.
```

### Architect Prompt for Matter tests
```text
Can you analyze the tests in test_coring.py, specifically test_matter_class and test_matter and create equivalent Rust tests for the structs and traits just created in matter.rs.  Please use Rust testing best practices but keep the tests functional equivalent to the Python versions.  Pay particular attention to ensuring compatibility.
```

```test
In src/matter.rs there are incorrect uses of pysodium which is not a library that exists.  Can you replace those calls with the appropriate sodiumoxide calls?
```

```test
```

### Prompt #3: Implement Basic CESR Data Structures
```text
In the `lib.rs` file, create a `mod cesr;` and a `cesr.rs` file with:
- Basic structs: `Matter`, `Signature`, `KeyPair` (as placeholders).
- Implement any relevant fields with placeholders (e.g., `pub struct Prefix { pub value: String }`, etc.).
- Derive Debug, Clone, PartialEq for each.
- Add minimal doc comments explaining the purpose of each.

Then add a small test in `cesr.rs` or `tests/cesr_tests.rs` to verify struct creation works.
```

### Prompt #4: CESR Serialization & Deserialization
```
Expand `cesr.rs` with:

1. Functions `serialize_cesr` and `deserialize_cesr` that operate on the new structs (e.g., `Prefix`) using a simple approach (like turning them into JSON strings for now).
2. If needed, define separate encoding functions for each struct. For example, `fn encode_prefix(prefix: &Prefix) -> String`.
3. Write unit tests that show round-trip serialization: create a `Prefix`, serialize it, deserialize it, then compare the original and new struct.
```

### Prompt #5: Enhanced Tests & KERIpy Compatibility
```
Using the existing `cesr.rs`, please add tests that mirror KERIpy’s CESR test data:

- If available, replicate known sample data from KERIpy (like known prefix strings).
- Validate that `serialize_cesr` and `deserialize_cesr` produce the same results as KERIpy's references.

Keep the tests in `tests/cesr_tests.rs` or an equivalent approach, ensuring we maintain separation of production code and tests.
```

### Prompt #6: Parser Module Setup
```
Create a new module `parser.rs` and a corresponding `mod parser;` in `lib.rs`. 
In `parser.rs`, create a `Parser` struct with placeholder functions:
- `parse_cesr_data(&self, data: &[u8]) -> Result<Vec<Prefix>, Error>`

Initially, just parse JSON arrays of prefix objects from a byte slice. 
Include a basic test in `tests/parser_tests.rs` verifying that valid JSON input is correctly turned into `Prefix` structs.
```

### Prompt #7: Integrate serde for Parsing
```
Refine the `Parser` so it uses `serde_json`:
- Convert bytes to string
- Parse into Rust structs
- Return the resulting vector of `Prefix`
Add error handling for malformed input.
Write tests with both valid and invalid JSON to ensure correctness.
```

### Prompt #8: Introduce a Validator Trait & Crypto
```
In a new file `validator.rs`, define:
- A `Validator` trait with a function `validate_prefix(&self, prefix: &Prefix) -> Result<(), Error>`.
- A struct `BasicValidator` implementing `Validator`.

Also set up the `libsodium` initialization in `main.rs` or `lib.rs` (calling `sodiumoxide::init()`).
For now, the validation can be a stub that checks string length, etc. We'll expand it later to real Ed25519 checks.
```


### Prompt #9: Synchronous Event Validation & Escrow Setup (Skeleton)
```
Create a module `kevery.rs` with:
1. A `Kevery` struct that holds a `Validator`.
2. A function `process_prefix(&mut self, prefix: Prefix) -> Result<(), Error>`.
3. A simple in-memory "escrow" vector for invalid prefixes.

For now, `process_prefix` calls `validate_prefix`. If validation fails, store the prefix in the escrow vector. 
Write tests in `tests/kevery_tests.rs`.
```

### Prompt #10: Storage Abstraction & LMDB Implementation
```
Create `storage.rs` with:
- A `Storage` trait (async) specifying methods like `get_prefix`, `put_prefix`, etc.
- A struct `LmdbStorage` implementing `Storage` for persistent operations.

Use `tokio`-compatible LMDB crate or an approach that is recommended for Rust + LMDB. 
Write minimal unit tests for `LmdbStorage` in `tests/storage_tests.rs`.
```

### Prompt #11: Integrating Kevery with Storage
```
In `kevery.rs`, update `Kevery` to accept a `Box<dyn Storage>` or similar. 
When validation succeeds, store the prefix in LMDB. If it fails, escrow it. 
Add a method `retry_escrowed_events(&mut self)` that re-validates items from escrow. 
Write or update tests to ensure that valid data ends up in LMDB while invalid data stays in escrow.
```

### Prompt #12: Hab & Habery Setup
```
Create `hab.rs` with:
- A `Hab` struct that wraps a single prefix + key management
- Methods for creating new keys (stub with libsodium for now)
Create `habery.rs` with:
- A `Habery` struct that manages multiple `Hab` instances in a HashMap
- Use fine-grained concurrency with `RwLock` or something similar

Add tests verifying you can create multiple `Hab` instances in `Habery`.
```

### Prompt #13: Key Management & Encryption
```
Refine `Hab` so it uses a pluggable key management trait:
- Trait: `KeyManager` with methods like `generate_keypair()`, `sign()`, etc.
- Default implementation with libsodium
Add optional encryption-at-rest toggles in `KeyManager` (left stubbed if needed).
Update tests to confirm we can generate keys, sign data, and verify signatures.
```

### Prompt #14: Event Import/Export
```
In `habery.rs` or a new file `io.rs`, implement:
- `export_events(&self) -> Vec<u8>` that returns a CESR event stream
- `import_events(&mut self, data: &[u8]) -> Result<(), Error>` that parses the stream and revalidates each event

Add tests verifying:
- Export produces a valid stream
- Import can parse and re-validate, storing events in LMDB or escrow if invalid
```

### Prompt #15: Final Testing & Documentation
```
1. Add doc comments (///) for all public structs, traits, and methods.
2. Ensure each module has thorough unit tests matching KERIpy coverage.
3. Provide at least one end-to-end example in `examples/` or doc tests:
   - Create a new `Habery`, generate a few events, validate them, store them, then export and import them.

At the end, please do a final pass to ensure there's no unused or orphaned code. 
```

## How to Use These Prompts
1.	Start with Prompt #1 in a fresh code-generation session. Wait for the LLM to produce the initial code (Cargo project, main.rs).
2.	Review and save that code (e.g., commit it).
3.	Proceed to Prompt #2, paste it into the same or a new session (depending on your workflow).
4.	Continue step by step, ensuring each prompt’s output is integrated into your codebase.

By the end, you’ll have an incremental, well-structured codebase that closely follows KERIpy’s design while taking advantage of Rust’s idioms and best practices.

