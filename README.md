# KERI Library (libkeri)

## Key Event Receipt Infrastructure (KERI) in Rust

The Key Event Receipt Infrastructure (KERI) is a system designed to provide a secure identity basis using cryptographic key management, rotation and verification.

This repository contains a Rust implementation of KERI, designed to be used as a C-callable library. The implementation follows the [KERI Protocol Specification](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html).

## Description

KERI provides a secure foundation for decentralized identity management. Unlike traditional Public Key Infrastructure (PKI), which relies on centralized certificate authorities, KERI enables secure key rotation without the need for a central authority.

From a reliability engineering perspective, KERI solves key management problems in a portable, interoperable, and secure manner.

Features of this implementation:

- C-compatible library interface for cross-language integration
- Designed after the KERIpy class structure and naming convention (using Rust idioms where appropriate)
- Minimalist approach with few dependencies
- High performance and memory efficiency
- Cross-platform support

## Installation

### Prerequisites

- Rust 1.85 or later
- Cargo

### Building from Source

```bash
git clone https://github.com/WebOfTrust/kerir.git
cd kerir
cargo build --release
```

### Using as a Dependency

```toml
[dependencies]
kerir = { git = "https://github.com/WebOfTrust/kerir.git" }
```

## C-Callable Library

This implementation is designed as a C-callable library, allowing integration with applications written in C, C++, and other languages that support the C ABI. The library exposes a set of functions that can be called from C code to interact with KERI functionality.

### Using the C API

```c
#include "kerir.h"

int main() {
    // Initialize KERI context
    KERI_Context* ctx = keri_init();
    
    // Generate a new identifier
    const char* identifier = keri_generate_identifier(ctx);
    
    // Clean up
    keri_free_context(ctx);
    
    return 0;
}
```

## Examples

### Key Management

```rust
use kerir::keri::keri::Keri;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new KERI instance
    let keri = Keri::new()?;
    
    // Generate a new identifier
    let (identifier, keypair) = keri.incept()?;
    
    // Rotate the identifier's keys
    let new_keypair = keri.rotate(identifier, keypair)?;
    
    // Verify events
    let verification = keri.verify(identifier)?;
    println!("Verification result: {}", verification);
    
    Ok(())
}
```

### Database Operations

```rust
use kerir::keri::db::lmdber::LMDBer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a database
    let db = LMDBer::builder()
        .name("my_database")
        .temp(true)
        .build()?;
        
    // Open a database and perform operations
    let env = db.env().unwrap();
    let db_handle = env.create_db(Some("test_db"), lmdb::DatabaseFlags::empty())?;
    
    // Insert data
    let key = b"example_key".to_vec();
    let value = b"example_value".to_vec();
    db.put_val(&db_handle, &key, &value)?;
    
    // Retrieve data
    if let Some(retrieved) = db.get_val(&db_handle, &key)? {
        println!("Retrieved: {}", String::from_utf8_lossy(&retrieved));
    }
    
    Ok(())
}
```

## API Documentation

Generate and view the API documentation with:

```bash
cargo doc --open
```

## Project Status

This project is under active development. Not all features of the KERI protocol specification have been implemented yet.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## References

- [KERI Specification](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- [KERI Python Implementation](https://github.com/WebOfTrust/keripy)
- [KERI JavaScript Implementation](https://github.com/WebOfTrust/keriJS)