#pragma once


#include <cstdint>
#include <vector>
#include <span>
#include <string>

#include "block/BlockCipher.h"


namespace block {

class AES final : public BlockCipher {
public:


	std::vector<uint32_t> Subkeys;

	uint8_t GFMult(int i, uint8_t s) const;

	void generateKeys(std::string key);

	void encrypt_block128(uint8_t *p) const;

	void encrypt_block192(uint8_t *p) const;

	void encrypt_block256(uint8_t *p) const;

	void decrypt_block128(uint8_t *p) const;

	void decrypt_block192(uint8_t *p) const;

	void decrypt_block256(uint8_t *p) const;

	size_t blockSize() const noexcept override;

	void encryptBlock(uint8_t *block) const override;

	void decryptBlock(uint8_t *block) const override;

	std::vector<uint8_t> encrypt(std::span<const uint8_t> plt) const;

	std::vector<uint8_t> decrypt(std::span<const uint8_t> plt) const;


};

} // namespace block
