# Rust Implementation of KERI (Key Event Receipt Infrastructure)

## 1. Overview
This project aims to develop a Rust implementation of the **KERI** (Key Event Receipt Infrastructure) specification, using **KERIpy** as the reference implementation. The Rust version should maintain functional parity while adhering to **Rust idioms and best practices**.

## 2. Development Approach
- **Incremental Development:**
    1. Implement **CESR primitive classes**
    2. Develop a **CESR parser**
    3. Implement **Kevery (event validation and processing)**
    4. Build the **Hab and Habery class hierarchy**
- **Follow KERIpy's modular design** while adapting to Rust's strengths.
- **Async-first architecture** powered by `tokio`.

---

## 3. Core Requirements

### 3.1. Code Architecture
- **Language & Runtime:** Rust with `tokio` async runtime.
- **Cryptographic Operations:**
    - Use Rust-native libraries where possible.
    - **Ed25519 operations must use libsodium**.
    - Allow cryptographic agility for alternative signature schemes.
- **Storage Layer:**
    - Trait-based abstraction for database backends.
    - First implementation: **LMDB**.
- **Key Management:**
    - Pluggable interface.
    - First implementation: **Software-based key storage with optional encryption (libsodium)**.
- **Concurrency & Caching:**
    - Fine-grained locks (`RwLock` per `Hab`).
    - Key state cache with LRU eviction.

### 3.2. Serialization & Data Handling
- **CESR serialization must be implemented in this library.**
- **Serde** for JSON serialization (where applicable).
- **Streaming event loading** instead of in-memory preloading.
- **Event persistence upon processing (no batching).**

### 3.3. Event Processing & Validation
- **Strict validation:** All events undergo full validation before being stored.
- **Escrow mechanism:** Events that fail validation are temporarily held in escrow.
- **Escrow retry:** Runs as a background task with **configurable per-escrow retry intervals**.
- **Event replay:** Must be sequential to preserve order guarantees.

### 3.4. Error Handling & Logging
- **Use `thiserror` for structured errors.**
- **Errors should closely map to KERIpy's error handling approach.**
- **Logging with `tracing`:**
    - Failed escrow retries logged at `DEBUG` level.
    - Detailed error messages included in logs.

---

## 4. Storage & Caching
- **Database:** LMDB (with pluggable backends in the future).
- **Escrowed events stored in the same database.**
- **Key state cache with LRU eviction policy (fixed size).**
- **No database snapshots; state recovery via event replay.**

---

## 5. API Design

### 5.1. Storage & Key Management
- **Storage abstraction as a trait** (to allow multiple backends).
- **Key storage as a separate async trait**.
- **Encryption optional/configurable (via libsodium).**

### 5.2. Event Handling
- **Event validation must be synchronous** before persistence.
- **Import/export of events in CESR event stream format.**
- **Import mechanism:**
    - **All imported events are fully re-validated**.
    - Events are parsed using the CESR stream parser.
- **Escrow Management API:**
    - List escrowed events.
    - Trigger revalidation.
    - Manually remove events from escrow (silent removal allowed).

### 5.3. Concurrency & Communication
- **Use `tokio::mpsc` channels** for async message passing.
- **Concurrent operations allowed on multiple `Hab` instances.**

---

## 6. Testing & Quality Assurance
- **Follow KERIpy's test structure** while using Rust idiomatic testing.
- **Unit tests first, integration tests later.**
- **Use additional testing libraries (`proptest`, `mockall`) where appropriate.**
- **Event log import/export must be tested against KERIpy’s reference implementation.**

---

## 7. Documentation & Developer Support
- **Comprehensive Rustdoc comments on all public APIs.**
- **Example usage guides showcasing Rust-specific idioms.**
- **Focus on developers already familiar with KERIpy.**

---

## 8. Future Considerations
- **Extensibility:**
    - Pluggable storage and key management backends.
    - Support for alternative transport mechanisms beyond `tokio::mpsc`.
- **Optimizations:**
    - Profiling and benchmarking tools may be added later.
- **CLI Interface:**
    - To be developed after core library is complete.

---

## Conclusion
This specification provides a clear, structured roadmap for implementing KERI in Rust. With a **modular, async-first design**, it maintains strict **compatibility with KERIpy** while optimizing for **Rust idioms and performance**.

This document can now be handed off to developers to **begin implementation**.

---
