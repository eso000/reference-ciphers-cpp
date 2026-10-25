#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "block/BlockCipher.h"

namespace block {

class Blowfish final : public BlockCipher {
public:


	std::array<uint32_t, 256> SBoxes0{};
	std::array<uint32_t, 256> SBoxes1{};
	std::array<uint32_t, 256> SBoxes2{};
	std::array<uint32_t, 256> SBoxes3{};
	std::vector<uint32_t> Subkeys;


	void generateKeys(std::span<const uint8_t> key);

	size_t blockSize() const noexcept override;

	void encryptBlock(uint8_t *block) const override;

	void decryptBlock(uint8_t *block) const override;

	std::vector<uint8_t> encrypt(std::span<const uint8_t> plt, std::span<const uint8_t> iv) const;

};

} // namespace block
