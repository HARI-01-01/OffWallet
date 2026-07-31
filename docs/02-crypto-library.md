# Module 1: Shared Cryptographic Library

## Overview
- Purpose: Cross-platform cryptographic primitives for offline payments
- Algorithms: ed25519, AES-256-GCM, SHA-256, CBOR
- Platforms: Android (Kotlin), Backend (Python)

## API Reference
- KeyManager: generateKeyPair, publicKeyToBytes, privateKeyToBytes
- Signer: sign, verify
- Encryptor: encrypt, decrypt
- Hasher: sha256
- Serializer: encode, decode

## Test Vectors
- ed25519 Signature Test
- AES-GCM Encryption Test
- SHA-256 Hash Test
- CBOR Serialization Test
