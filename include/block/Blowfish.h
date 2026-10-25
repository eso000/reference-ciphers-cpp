#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "block/BlockCipher.h"

namespace block {

class Blowfish final : public BlockCipher {
public:
	
	
	std::vector<uint32_t> SBoxes0;
	std::vector<uint32_t> SBoxes1;
	std::vector<uint32_t> SBoxes2;
	std::vector<uint32_t> SBoxes3;
	std::vector<uint32_t> Subkeys;
	
	

	void generateKeys(const std::vector<uint8_t>& key);
	
	size_t blockSize() const noexcept override;

	void encryptBlock(uint8_t *block) const override;

	void decryptBlock(uint8_t *block) const override;

	std::vector<uint8_t> encrypt(std::span<const uint8_t> plt, std::span<const uint8_t> iv) const;

};

} // namespace block
