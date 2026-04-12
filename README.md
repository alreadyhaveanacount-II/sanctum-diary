# Sanctum

A local, encrypted diary application for Windows. Entries are protected with ChaCha20-Poly1305 authenticated encryption, and the master key is derived from your password using scrypt.

## Features

- **Encrypted at rest** — all entries are encrypted using ChaCha20-Poly1305 (AEAD)
- **Configurable key derivation** — scrypt parameters (N, r, p) are chosen at diary creation and stored in the vault header
- **Windows Hello integration** — the session key can be wrapped/unwrapped using Windows Hello for seamless re-authentication
- **Auto-lock** — diary locks automatically after 60 seconds of inactivity
- **Secure memory handling** — sensitive buffers are zeroed after use and locked in memory to prevent swapping
- **Entry searching** — allows searching for entries via title or date
- **Immediate UI** — built with [Dear ImGui](https://github.com/ocornut/imgui) + OpenGL/GLFW, no dependencies on heavy GUI frameworks

## Cryptographic Implementations

All cryptographic primitives are implemented from scratch — no OpenSSL, libsodium, or OS crypto APIs are used for the core cipher work.

| Primitive | Notes |
|---|---|
| ChaCha20-Poly1305 | AVX-512 optimized; processes multiple blocks in parallel using 512-bit registers |
| SHA-256 | Portable scalar implementation (no SHA-NI) |
| scrypt | Built on top of the ChaCha20 and SHA-256 implementations above |

All implementations are validated against the official IETF/NIST test vectors for their respective primitives.

## Vault Format

Each `.sdde` file is a flat binary with the following layout:

```
[16 bytes — salt (plaintext)]
[16 bytes — scrypt parameters: N (8 bytes LE) + r (4 bytes LE) + p (4 bytes LE)]
[Validation entry]
[Entry 1]
[Entry 2]
...
```

Each entry is serialized as:

```
[16 bytes — Poly1305 authentication tag]
[12 bytes — ChaCha20 nonce]
[ 8 bytes — timestamp (LE)]
[ 8 bytes — title length (LE)]
[ 8 bytes — content length (LE)]
[N bytes — encrypted title + content (concatenated, single ciphertext)]
```

The first entry after the header is a random validation entry: 32 bytes of CSPRNG data encrypted with the derived key. On open, decrypting it and verifying the Poly1305 tag confirms the key is correct without relying on any known plaintext. On every save it is replaced with a freshly randomized entry.

## Building

Requirements:
- Windows (Windows Hello APIs are used for session key wrapping)
- Preferrably AVX-512 capable CPU(for speed, but works on other CPUs due to Clang Extended Vectors)
- Clang with C++20 support
- GLFW3 (`glfw3.dll` must be present alongside the executable)

```bat
build.bat
```

The build script compiles `main.cpp` alongside all ImGui sources in `include/imgui/`.

## Usage

1. Launch `Sanctum.exe`
2. Enter a path for a new or existing diary (without the `.sdde` extension)
3. **New diary:** choose your scrypt parameters (N exponent, r, p) and enter a password — parameters are stored in the vault and never need to be entered again
4. **Existing diary:** enter your password — parameters are read from the vault automatically
5. Create, view, edit, and delete entries
6. The diary auto-locks after 60 seconds out of focus; unlock with Windows Hello

## Security Notes

- scrypt parameters are configurable at creation time. Higher N increases key derivation cost and resistance to offline attacks. The parameters are stored unencrypted in the vault header — this is intentional, as they contain no secret information.
- Title and content are concatenated into a single plaintext before encryption. The lengths are stored in the header so they can be split on decryption. This means the tag covers both fields together.
- Nonces are generated randomly per entry using a CSPRNG. A fresh nonce is generated whenever an entry is created or re-saved.
- `CryptoHelper::secure_zero_memory` is used on all sensitive buffers before deallocation to prevent secrets from lingering in process memory.
- Windows Hello key wrapping is a session convenience feature — the raw derived key is never written to disk in any form.

## How to link Sanctum to .sdde files

1. Launch cmd in Administrator mode
2. Run
   ```bat
   assoc .sdde=SanctumDiary
   ftype SanctumDiary="C:\caminho\para\sanctum.exe" "%1"
   ```

## Attribution
[Icon.ico created by Marsiholo - Flaticon](https://www.flaticon.com/free-icons/secret)

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
