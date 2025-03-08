# Quantum-Safe Multi-Signature Wallet

This project implements a quantum-safe multi-signature wallet using SPHINCS+ for quantum-resistant cryptography and supports Hardware Security Modules (HSMs) for secure key storage.

## Features
 Quantum-safe signing with SPHINCS+  
 Multi-signature transaction verification  
 HSM integration for secure key storage  
 CLI-based signing and verification  

## How to Run
```sh
cargo build --release
cargo run -- --sign Alice
cargo run -- --verify

