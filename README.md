# 🛡️ nofuture.go — Ephemeral Post-Quantum Text Encryption

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org)
[![Security Hardened](https://img.shields.io/badge/security-hardened-brightgreen.svg)](#)
[![Status: Experimental](https://img.shields.io/badge/status-experimental-yellow.svg)](#)

**nofuture.go** is a secure, ephemeral text encryption application designed to facilitate private communication — even across untrusted platforms — using post-quantum cryptography, memory-hard key management, and a local virtual keyboard for anti-keylogger defense.

Its core purpose is simple but powerful:

> 💬 **Encrypt sensitive text, exchange it via any mainstream chat, and make the keys disappear forever.**

---

## 📦 Project Structure

- `cmd/` — CLI and runtime entry points
- `internal/crypto` — Kyber, Dilithium, Argon2, BLAKE2b, XChaCha
- `internal/memory` — memguard-backed key handling
- `assets/` — frontend static files (keyboard UI, etc.)
- `USAGE.md` — basic usage guide

---

## 📖 Documentation

- ✅ [How it works](#session-flow)
- ✅ [Cryptographic primitives](#cryptographic-primitives)
- ✅ [Memory protection](#key-generation--memory-protection)
- ✅ [Virtual keyboard](#virtual-keyboard-anti-keylogger)
- ✅ [Usage example](USAGE.md)

---

## 🔐 Cryptographic Primitives

- **Kyber1024-90s** (Post-Quantum Key Encapsulation - KEM)  
  > Used to establish a shared session key between users.

- **Dilithium5-AES** (Post-Quantum Digital Signature - PQDS)  
  > Used for optional mutual authentication and message verification.

- **BLAKE2b-512**  
  > Used in session binding and secure hash-based key derivation.

- **XChaCha20-Poly1305**  
  > Used for symmetric encryption of the actual message content.

- **argon2id** with OWASP-recommended parameters  
  > Memory-hard key derivation used for passphrases and session binding.

---

## 🧠 Key Generation & Memory Protection

- All cryptographic keys are generated **in volatile memory (RAM)**.
- Sensitive buffers (session keys, private keys, derived secrets) are stored using [`memguard`](https://github.com/awnumar/memguard), a secure memory management library for Go.
- `memguard`:
  - Locks memory pages (`mlock`) to prevent swapping.
  - Encrypts memory buffers while in RAM.
  - Prevents access from other users — including the root user or malware.
  - Performs secure erasure when buffers are destroyed or on crash.

> ✅ **No key material ever touches the disk or garbage-collected heap.**

---

## 🖱️ Virtual Keyboard (Anti-Keylogger)

To protect local input from keyloggers or spyware, `nofuture.go` integrates an **optional on-screen virtual keyboard** with randomized key layout.

- Protects against keyloggers reading `/dev/input` or `stdin`.
- No physical keypress events are generated.
- Layout is randomized per session.
- Optional use, recommended for high-security environments.

---

## 🔁 Session Flow

Encrypted communication is based on shared **Session IDs**, which encapsulate the cryptographic context between two users.

### 🔸 Phase 1: Create Session

- Generate a key pair using Kyber KEM.
- Derive a session key and unique **Session ID**.
- All key material is held in memory and locked by `memguard`.

### 🔸 Phase 2: Share Session ID

- Copy the Session ID and send it to your contact using **any chat platform**.
- Session IDs **do not contain sensitive data**.
- Transmission over unencrypted channels (chat, email) is acceptable, but encrypted ones are recommended.

### 🔸 Phase 3: Synchronize Session

- Your contact imports the Session ID into their instance of `nofuture.go`.
- The app performs a key agreement and mutual validation (using Dilithium signatures if enabled).
- Once both sides are synchronized, they can start exchanging encrypted text.

---

## 💥 End Session = Total Key Destruction

When you end the session:

- All keys are securely wiped using `memguard.Purge()`.
- Session memory is sanitized according to [NIST SP 800-88](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final).
- No forensic recovery is possible — not even with root access or RAM snapshots.
- The ciphertext remains in your chat app, but **can never be decrypted again**.

> 🔐 One conversation. One key. One chance to read. No future access.

---

## 📄 Usage Example

See [USAGE.md](USAGE.md) for a full guide on how to use `nofuture.go` alongside a browser-based chat client.

---

## 📜 License

MIT License — see [`LICENSE`](./LICENSE)

---

## ✊ Built with love and defiance  
Because **privacy isn’t a feature** — it’s a human right.




