# Sanctum

A local, encrypted diary application for Windows. Entries are protected with ChaCha20-Poly1305 authenticated encryption, and the master key is derived from your password using scrypt.

## Features

- **Encrypted at rest** — all entries are encrypted using ChaCha20-Poly1305 (AEAD)
- **Password-based key derivation** — scrypt (N=131072, r=8, p=1) ensures brute-force resistance
- **Windows Hello integration** — the session key can be wrapped/unwrapped using Windows Hello for seamless re-authentication
- **Auto-lock** — diary locks automatically after 60 seconds of inactivity
- **Secure memory handling** — sensitive buffers are zeroed after use and locked in memory to prevent swapping
- **Immediate UI** — built with [Dear ImGui](https://github.com/ocornut/imgui) + OpenGL/GLFW, no dependencies on heavy GUI frameworks

## Cryptographic Implementations

All cryptographic primitives are implemented from scratch — no OpenSSL, libsodium, or OS crypto APIs are used for the core cipher work.

| Primitive | Notes |
|-------------------|----------------------------------------------------------------------------------|
| ChaCha20-Poly1305 | AVX-512 optimized; processes multiple blocks in parallel using 512-bit registers |
| SHA-256           | Portable scalar implementation (no SHA-NI)                                       |
| scrypt            | Built on top of the ChaCha20 and SHA-256 implementations above                   |

All implementations are validated against the official IETF/NIST test vectors for their respective primitives.

## Vault Format

Each `.sdde` file is a flat binary with the following layout:

```
[16 bytes — salt (plaintext)]
[Validation entry — title: "TEST ENTRY", content: "IS KEY VALID"]
[Entry 1]
[Entry 2]
...
```

Each entry is serialized as:

```
[16 bytes — Poly1305 authentication tag]
[12 bytes — ChaCha20 nonce]
[ 8 bytes — title length (LE)]
[ 8 bytes — content length (LE)]
[N bytes — encrypted title]
[M bytes — encrypted content]
```

The validation entry is written on diary creation and used to verify the password on every subsequent open, without exposing a known-plaintext oracle (the key is verified, not the password itself).

## Building

Requirements:
- Windows (Windows Hello APIs are used for session key wrapping)
- Clang with C++20 support
- GLFW3 (`glfw3.dll` must be present alongside the executable)

```bat
build.bat
```

The build script compiles `main.cpp` alongside all ImGui sources in `include/imgui/`.

## Usage

1. Launch `main.exe`
2. Enter a path for a new or existing diary (without the `.sdde` extension)
3. Enter your password — the key is derived and never stored on disk
4. Create, view, edit, and delete entries
5. The diary auto-locks after 60 seconds out of focus; unlock with Windows Hello

## Security Notes

- The scrypt parameters (N=131072) are intentionally expensive to resist offline attacks. Expect ~1–3 seconds on first unlock.
- Nonces are generated randomly per entry; tag+nonce uniqueness is the caller's responsibility for entries that are re-saved.
- `CryptoHelper::secure_zero_memory` is used on all sensitive buffers before deallocation to prevent secrets from lingering in process memory.
- Windows Hello key wrapping is a session convenience feature — the raw derived key is never written to disk in any form.

## Project Structure

```
main.cpp                        — Application entry point and render loop
include/
  app_state.hpp                 — Global application state (g_state)
  app_pages.hpp                 — All ImGui page/screen implementations
  encryption/
    aead/chacha20_poly1305.hpp  — AEAD construction
    primitives/chacha20.hpp     — ChaCha20 stream cipher
    primitives/poly1305.hpp     — Poly1305 MAC
  hash/sha256.hpp               — SHA-256
  kdf/scrypt.hpp                — scrypt key derivation
  utils/
    crypto_helpers.hpp          — Secure memory, Windows Hello, CSPRNG
    diary_helper.hpp            — Entry serialization/deserialization
    file_ops.hpp                — Binary file I/O
  imgui/                        — Dear ImGui source (vendored)
  GLFW/                         — GLFW headers
```