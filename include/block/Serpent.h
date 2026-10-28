#pragma once

#include <cstdint>
#include <vector>
#include <span>

#include "block/BlockCipher.h"

namespace block {

class Serpent final : public BlockCipher {
  public:
    std::vector<uint32_t> Subkeys;

    void applySBox(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int n) const;

    void applyInvSBox(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int n) const;

    void generateKeys(std::span<const uint8_t> key);

    void encrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3) const;

    void decrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3) const;

    size_t blockSize() const noexcept override;

    void encryptBlock(uint8_t *block) const override;

    void decryptBlock(uint8_t *block) const override;

    std::vector<uint8_t> encrypt(std::span<const uint8_t> plt) const;

    std::vector<uint8_t> decrypt(std::span<const uint8_t> plt) const;
};

} // namespace block
