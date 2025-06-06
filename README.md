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

## 📜 License

MIT License — see [`LICENSE`](./LICENSE)

---

## ✊ Built with love and defiance  
Because **privacy isn’t a feature** — it’s a human right.



