# reference-ciphers-cpp

[![CI](https://github.com/eso000/reference-ciphers-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/eso000/reference-ciphers-cpp/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-C%2B%2B20-blue)](https://isocpp.org/)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

From-scratch, dependency-free reference implementations of five classic block ciphers in C++20 — AES, DES, Blowfish, Twofish and Serpent — together with the six classic modes of operation and the usual padding schemes. Every cipher is checked against its official published test vectors.

This is the C++ sibling of [`refciphers`](https://github.com/eso000/reference-ciphers-python) and [`reference-ciphers-c`](https://github.com/eso000/reference-ciphers-c). The implementations are developed with the same test vectors and exercise the same algorithms.

Written to be read, and written to be checked.

## Security notice

**This is an educational, from-scratch implementation. Do not use it to protect real secrets.**

- It is **not constant-time** and makes **no side-channel claims**. The cipher implementations use table lookups and branches that leak through timing and cache behaviour.
- It provides **no authenticated encryption** — no MAC and no AEAD. Ciphertexts are malleable.
- It has **no key derivation** and no protection against misuse, and it has **not been audited**.

Use a vetted, maintained library such as OpenSSL or libsodium for anything that matters.

## Ciphers

| Cipher   | Block size      | Key sizes        | Standard / source                  |
|----------|-----------------|------------------|------------------------------------|
| AES      | 16 bytes (128 b)| 16 / 24 / 32     | FIPS-197                           |
| DES      | 8 bytes (64 b)  | 8 (56 b + parity)| FIPS 46-3                          |
| Blowfish | 8 bytes (64 b)  | 4–56 (32–448 b)  | Bruce Schneier, FSE 1993           |
| Twofish  | 16 bytes (128 b)| 16 / 24 / 32     | AES submission (Schneier et al.)   |
| Serpent  | 16 bytes (128 b)| 1–32             | NESSIE finalist (Anderson et al.) |

## Modes and padding

Six modes of operation are shared by every cipher through the `BlockCipher` base class:

- **ECB, CBC, PCBC, CFB, OFB, CTR** — all implemented in a common mode layer.
- **Block modes (ECB, CBC, PCBC)** operate on whole blocks and support padding. Schemes: `Padding::None`, `Padding::Zeros`, `Padding::PKCS7`, `Padding::ANSIX923`, `Padding::ISO78164`. `Padding::None` requires block-aligned input. `Padding::PKCS7`, `Padding::ANSIX923` and `Padding::ISO78164` always add a padding block, even when the message is aligned; `Padding::Zeros` only fills up to the next block boundary, so empty and aligned messages are not extended.
- **`Padding::Zeros` cannot be removed unambiguously**: zero padding is indistinguishable from genuine zero bytes at the end of the message, so `unpad` removes nothing for this scheme. The caller must trim trailing zeros or retain the original length, and trimming loses any genuine trailing zero bytes. Use a strict scheme such as `PKCS7` when the data may end in zeros.
- **Unpadding** is validated: a malformed strict padding or an empty ciphertext with a strict scheme is an error, not silently-returned data.
- **Stream-like modes (CFB, OFB, CTR)** work on arbitrary lengths and ignore the padding argument, so the ciphertext is exactly as long as the plaintext.
- An IV is required for every mode except ECB and must be exactly one block long; a wrong-sized IV is an error rather than being silently adjusted.
- `encryptBlock()`/`decryptBlock()`, every mode method and the file methods throw `std::logic_error` until `generateKeys()` has completed successfully. A failed `generateKeys()` leaves the cipher unusable rather than exposing a partial key schedule.

## Design

- **Object-oriented API**: Each cipher inherits from the abstract `BlockCipher` base class, which provides shared bit manipulation, endianness helpers, and mode implementations.
- **Shared infrastructure**: Bitwise helpers (`rotl`, `rotr`, byte extraction, big/little-endian load/store) are free functions in the private `src/bits.h` (`block::detail`), shared by the cipher implementations instead of being copied into each one.
- **Constant tables**: S-boxes and the like are `inline constexpr std::array` objects in `src/*_data.h` (`block::tables::<cipher>`), shared by every instance. A cipher object holds only its key schedule.
- **Spans, not pointers**: The mode methods take `std::span` (`encryptCBC(data, iv)`), so a buffer and its length travel together. Keys are passed as `std::span<const uint8_t>`, like the C and Python siblings. Everything lives in the `block` namespace.
- **Optimized implementations**: AES uses T-tables for efficient round computation; hot paths are marked with `__attribute__((always_inline))` where beneficial.
- **Unified testing**: A shared `TestBase` framework and centralized test vectors (`tests/vectors.h`) provide consistent known-answer and round-trip testing across all ciphers.

## Requirements

- A C++20 compiler with `<span>` and `<bit>` (tested with g++; GCC 10+ or Clang 10+). No third-party libraries, no runtime dependencies.
- `make` to build.

## Build and test

The repository root is the build root. All build artifacts are produced under `build/`.

```bash
make          # build all cipher tests
make test     # build and run all tests
make clean    # remove build/
```

You can also override the compiler:

```bash
make CXX=clang++ CXXFLAGS="-std=c++20 -O2 -Wall -Wextra -Wpedantic" test
```

For stricter builds (warnings as errors, sanitizers):

```bash
# Warnings as errors
make CXX=g++ CXXFLAGS="-std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror" test

# Address and undefined-behaviour sanitizers
make CXX=clang++ CXXFLAGS="-std=c++20 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined" test
```

## Example usage

```cpp
#include <iostream>
#include <vector>

#include "block/AES.h"
#include "block/BlockCipher.h"

int main() {
    block::AES aes;
    // Keys are raw bytes: 16, 24 or 32 for AES
    const std::vector<uint8_t> key = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    aes.generateKeys(key);

    // Plaintext
    std::vector<uint8_t> pt = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    // IV for CBC
    std::vector<uint8_t> iv(16, 0x00);

    // Encrypt with CBC + PKCS7 padding
    auto ct = aes.encryptMode(pt, block::BlockMode::CBC, block::Padding::PKCS7, iv);

    // Decrypt
    auto pt2 = aes.decryptMode(ct, block::BlockMode::CBC, block::Padding::PKCS7, iv);

    return 0;
}
```

Individual ciphers can also be used at the block level via `encryptBlock()`/`decryptBlock()`, and the base class provides in-place mode methods that take a `std::span` (`encryptCBC(data, iv)`, `decryptECB(data)`, etc.). The library also supports file encryption/decryption via `encryptFile()` and `decryptFile()` (which take a `std::filesystem::path` and use the `mode` and `padding` members).

## Testing and verification

Tests live in `tests/` and are built automatically by the Makefile:

- **Known-answer tests**: Every cipher is validated against official test vectors (FIPS-197 for AES, Schneier's official sets for Blowfish, Biham et al. for Serpent, published DES vectors, Twofish KATs).
- **Round-trip tests**: Multi-block encrypt/decrypt round trips verify correctness.
- **Unified framework**: `tests/TestBase.{h,cpp}` and `tests/vectors.h` provide a shared test harness, so each cipher's test suite focuses only on cipher-specific wiring.
- **All ciphers tested**: `make test` runs tests for AES, Blowfish, Twofish, DES, Serpent, and generic mode tests.

The test vectors in `tests/vectors.h` include provenance notes documenting their sources.

## Project layout

```
.
├── .github/workflows/ci.yml   # GCC/Clang + ASan/UBSan CI
├── include/block/             # Public headers (BlockCipher, AES, DES, Blowfish, Twofish, Serpent, Padding)
├── src/                       # Implementations, plus private helpers (bits.h, force_inline.h)
├── tests/                     # Test suites and shared test infrastructure
├── Makefile                   # Build configuration
├── README.md
├── LICENSE
├── .gitignore
└── build/                     # Generated binaries (after build)
```

## License

MIT — see [LICENSE](LICENSE). The code is provided as-is, for educational use; the security notice above still applies.
