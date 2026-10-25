#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <string>

#include "block/BlockCipher.h"

namespace block {

class DES final : public BlockCipher {
public:

	explicit DES(bool useAlt = true) : use_alt(useAlt) {}

	bool use_alt;


	std::vector<uint64_t> Subkeys;

	static uint64_t permutate(uint64_t x, std::span<const uint8_t> P, int base_size);

	uint64_t feistel(uint32_t r, int i) const;

	void round(uint32_t &l, uint32_t &r, int i) const;

	static uint64_t ip_perm_alt(uint64_t block);

	static uint64_t fp_perm_alt(uint64_t block);

	void generateKeys(std::string key);

	size_t blockSize() const noexcept override;

	void encryptBlock(uint8_t *block) const override;

	void decryptBlock(uint8_t *block) const override;

	std::vector<uint8_t> encrypt(std::span<const uint8_t> plt) const;

	std::vector<uint8_t> decrypt(std::span<const uint8_t> plt) const;

};

} // namespace block
