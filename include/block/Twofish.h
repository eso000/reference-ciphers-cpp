#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <span>
#include <string>

#include "block/BlockCipher.h"

namespace block {

class Twofish final : public BlockCipher {
public:


	std::array<uint32_t, 256> Sbox0{};
	std::array<uint32_t, 256> Sbox1{};
	std::array<uint32_t, 256> Sbox2{};
	std::array<uint32_t, 256> Sbox3{};

	std::vector<uint32_t> Subkeys;


	uint32_t multgf(uint32_t a,uint32_t b,uint32_t pol) const;

	uint8_t multgf(uint16_t a,uint16_t b) const;

	uint8_t RSAmul(int i, const uint8_t *p) const;

	void generateKeys(const std::vector<uint8_t>& key);

	size_t blockSize() const noexcept override;

	void encryptBlock(uint8_t *block) const override;

	void decryptBlock(uint8_t *block) const override;

	std::vector<uint8_t> encrypt(std::span<const uint8_t> plt, std::span<const uint8_t> iv) const;

};

} // namespace block
