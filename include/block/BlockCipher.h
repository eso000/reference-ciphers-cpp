#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

#include "block/Padding.h"

namespace block {

enum class BlockMode { ECB, CBC, PCBC, CFB, OFB, CTR };

class BlockCipher {
public:
	virtual ~BlockCipher() = default;

	/* The mode and padding the file functions below use. */
	BlockMode mode = BlockMode::ECB;

	Padding padding = Padding::PKCS7;

	[[nodiscard]] virtual size_t blockSize() const noexcept = 0;

	virtual void encryptBlock(uint8_t *block) const = 0;

	virtual void decryptBlock(uint8_t *block) const = 0;

	/* The mode functions work in place on `data`. Chained modes need an IV of
	   exactly one block and throw std::invalid_argument otherwise. A trailing
	   partial block is left untouched by ECB, CBC and PCBC and handled by the
	   keystream modes (CFB, OFB, CTR).

	   Where a mode advances the chaining value (decryptCBC, encryptPCBC and
	   decryptPCBC) the IV is a mutable span and holds the next chaining value
	   on return; the other modes only read it. */
	void encryptECB(std::span<uint8_t> data) const;

	void decryptECB(std::span<uint8_t> data) const;

	void encryptCBC(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	void decryptCBC(std::span<uint8_t> data, std::span<uint8_t> iv) const;

	void encryptPCBC(std::span<uint8_t> data, std::span<uint8_t> iv) const;

	void decryptPCBC(std::span<uint8_t> data, std::span<uint8_t> iv) const;

	void encryptCFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	void decryptCFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	void encryptOFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	void decryptOFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	void encryptCTR(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	void decryptCTR(std::span<uint8_t> data, std::span<const uint8_t> iv) const;

	std::vector<uint8_t> encryptMode(std::span<const uint8_t> plt, BlockMode mode,
			Padding padding, std::span<const uint8_t> iv = {}) const;

	std::vector<uint8_t> decryptMode(std::span<const uint8_t> plt, BlockMode mode,
			Padding padding, std::span<const uint8_t> iv = {}) const;

	/* Encrypt or decrypt a file in place with the `mode` and `padding` members.
	   The input is read and processed completely before the file is rewritten,
	   so an error leaves it untouched. A chained mode uses a fixed IV of 0xff
	   bytes, which is fine for demonstrations and not for real data. Throws
	   std::runtime_error when the file cannot be read or written, and the same
	   exceptions as encryptMode and decryptMode otherwise. */
	void encryptFile(const std::filesystem::path &path) const;

	void decryptFile(const std::filesystem::path &path) const;

protected:
	/* Set by a successful generateKeys() call. Every operation that needs the
	   key schedule checks it so an unkeyed cipher fails instead of silently
	   returning its input unchanged. */
	bool keySet = false;

	void requireKey() const;

private:
	void validateIV(std::span<const uint8_t> iv, BlockMode mode) const;

	void requireBlockIV(std::span<const uint8_t> iv) const;
};

} // namespace block
