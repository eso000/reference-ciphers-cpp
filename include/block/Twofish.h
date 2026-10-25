#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>

#include "block/BlockCipher.h"

namespace block {

class Twofish final : public BlockCipher {
public:
	Twofish();
	std::vector<std::vector<uint8_t>> RS;

	std::vector<std::vector<uint8_t>> MDS;
	std::vector<uint8_t> MDSEF;
	std::vector<uint8_t> MDS5B;
	
	std::vector<uint8_t> q0;
	std::vector<uint8_t> q1;


	std::vector<uint32_t> Sbox0;
	std::vector<uint32_t> Sbox1;
	std::vector<uint32_t> Sbox2;
	std::vector<uint32_t> Sbox3;

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
