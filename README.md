# AES
**Advanced Encryption Standard (AES) implementation in C**
- A lightweight C implementation targeting embedded systems, developed on Ubuntu (Windows 11, WSL2).

---

## Features
- Supports AES-128/192/256 bit key sizes
- Modes: ECB, CBC, CTR, GCM
- PKCS#7 padding for ECB/CBC modes
- Test vectors validation

---

## Build Instructions

### Default build
'''bash
make -j
'''
- Default configuration: **AES-128 ECB**

### Custom Configuration
Override 'TYPE' (key size) and 'MODE' (operation mode):
'''bash
make -j TYPE=256 MODE=GCM       # Example: AES-256 in GCM mode
'''
**Valid options**
- 'TYPE': '128', '192', '256'
- 'MODE': 'ECB', 'CBC', 'CTR', 'GCM'

### Outputs
- Main executable: 'build/main/main_test' (custom text)
- Test executable: 'build/test/aes_test' (validates test vectors)

---

## Usage

### Integration Guide
This implementation is designed for embedded systems with **single-mode operation**. To support multiple modes:
1. Modify mode switches in code via 'TYPE_AES_' and 'MODE_AES_' macros.
2. Reference 'main/main.c' and 'test/test.c' for API usage examples across modes.

---

## Critical Implementation Notes

#### 1. **Memory Management**
- **ECB/CBC modes**:
  - PKCS#7 padding is enforced.
  - 'ctx->output' is dynamically allocated - **caller must free memory**.
  - Use padded ciphertext for decryption.

- **CTR/GCM modes** (stream ciphers):
  - No padding required.
  - 'ctx->output' uses 16-byte-aligned buffers for XOR operations - **caller must free memory**.

#### 2. **GCM-Specific Workflow**
- **Encryption**
  1. Initialize with 'key', 'AAD', 'GHASH', 'J0'.
  2. Provide 'input' and 'input_len'.
  3. Output: 'ciphertext' + 'tag'.

- **Decryption**
  1. Initialize with 'key', 'AAD', 'GHASH', 'J0', and 'tag'.
  2. Tag verification occurs before decryption.
  3. Output: 'plaintext' (only if tag matches).

#### 3. **Preconditions**
- Ensure 'ctx->output = NULL' before encryption/decryption.
- Able to call 'aes_context_release()' to free allocated memory.

---