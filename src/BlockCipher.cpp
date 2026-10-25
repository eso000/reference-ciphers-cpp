#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "block/BlockCipher.h"

namespace block {

namespace {

/* The largest block size of any cipher here (AES, Twofish and Serpent). */
constexpr size_t MAX_BLOCK = 16;

using Block = std::array<uint8_t, MAX_BLOCK>;

void xorBlock(uint8_t *dst, const uint8_t *src, size_t n)
{
	for (size_t i = 0; i < n; ++i)
		dst[i] ^= src[i];
}

void incrementCounter(uint8_t *ctr, size_t n)
{
	for (size_t i = n; i-- > 0;)
		if (++ctr[i] != 0)
			break;
}

/* Copies the first n bytes of src into a fresh scratch block. */
Block loadBlock(const uint8_t *src, size_t n)
{
	Block b{};
	std::copy_n(src, n, b.begin());
	return b;
}

}

void BlockCipher::requireKey() const
{
	if (!keySet)
		throw std::logic_error("key schedule is not initialized; call generateKeys first");
}

void BlockCipher::requireBlockIV(std::span<const uint8_t> iv) const
{
	if (iv.size() != blockSize())
		throw std::invalid_argument("IV must be exactly " + std::to_string(blockSize())
				+ " bytes, got " + std::to_string(iv.size()));
}

void BlockCipher::encryptECB(std::span<uint8_t> data) const
{
	requireKey();
	const size_t bs = blockSize();
	for (size_t off = 0; off + bs <= data.size(); off += bs)
		encryptBlock(data.data() + off);
}

void BlockCipher::decryptECB(std::span<uint8_t> data) const
{
	requireKey();
	const size_t bs = blockSize();
	for (size_t off = 0; off + bs <= data.size(); off += bs)
		decryptBlock(data.data() + off);
}

void BlockCipher::encryptCBC(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	const uint8_t *prev = iv.data();
	for (size_t off = 0; off + bs <= data.size(); off += bs)
	{
		uint8_t *blk = data.data() + off;
		xorBlock(blk, prev, bs);
		encryptBlock(blk);
		prev = blk;
	}
}

void BlockCipher::decryptCBC(std::span<uint8_t> data, std::span<uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	for (size_t off = 0; off + bs <= data.size(); off += bs)
	{
		uint8_t *blk = data.data() + off;
		const Block cipherBlock = loadBlock(blk, bs);
		decryptBlock(blk);
		xorBlock(blk, iv.data(), bs);
		std::copy_n(cipherBlock.begin(), bs, iv.begin());
	}
}

void BlockCipher::encryptPCBC(std::span<uint8_t> data, std::span<uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	for (size_t off = 0; off + bs <= data.size(); off += bs)
	{
		uint8_t *blk = data.data() + off;
		Block next = loadBlock(blk, bs);
		xorBlock(blk, iv.data(), bs);
		encryptBlock(blk);
		xorBlock(next.data(), blk, bs);
		std::copy_n(next.begin(), bs, iv.begin());
	}
}

void BlockCipher::decryptPCBC(std::span<uint8_t> data, std::span<uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	for (size_t off = 0; off + bs <= data.size(); off += bs)
	{
		uint8_t *blk = data.data() + off;
		Block next = loadBlock(blk, bs);
		decryptBlock(blk);
		xorBlock(blk, iv.data(), bs);
		xorBlock(next.data(), blk, bs);
		std::copy_n(next.begin(), bs, iv.begin());
	}
}

/* The keystream modes can take a short final block: the cipher is run once
   more and only the bytes that remain are XORed. The feedback value that
   would follow the truncated block is never used, so it does not have to be
   computed or padded. */
void BlockCipher::encryptCFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	Block reg = loadBlock(iv.data(), bs);
	size_t off = 0;
	for (; data.size() - off >= bs; off += bs)
	{
		uint8_t *blk = data.data() + off;
		encryptBlock(reg.data());
		xorBlock(blk, reg.data(), bs);
		std::copy_n(blk, bs, reg.begin());
	}
	if (off < data.size())
	{
		encryptBlock(reg.data());
		xorBlock(data.data() + off, reg.data(), data.size() - off);
	}
}

void BlockCipher::decryptCFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	Block reg = loadBlock(iv.data(), bs);
	size_t off = 0;
	for (; data.size() - off >= bs; off += bs)
	{
		uint8_t *blk = data.data() + off;
		encryptBlock(reg.data());
		const Block cipherBlock = loadBlock(blk, bs);
		xorBlock(blk, reg.data(), bs);
		reg = cipherBlock;
	}
	if (off < data.size())
	{
		encryptBlock(reg.data());
		xorBlock(data.data() + off, reg.data(), data.size() - off);
	}
}

void BlockCipher::encryptOFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	Block reg = loadBlock(iv.data(), bs);
	size_t off = 0;
	for (; data.size() - off >= bs; off += bs)
	{
		encryptBlock(reg.data());
		xorBlock(data.data() + off, reg.data(), bs);
	}
	if (off < data.size())
	{
		encryptBlock(reg.data());
		xorBlock(data.data() + off, reg.data(), data.size() - off);
	}
}

void BlockCipher::decryptOFB(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	encryptOFB(data, iv);
}

void BlockCipher::encryptCTR(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	requireBlockIV(iv);
	const size_t bs = blockSize();
	Block ctr = loadBlock(iv.data(), bs);
	size_t off = 0;
	for (; data.size() - off >= bs; off += bs)
	{
		Block ks = ctr;
		encryptBlock(ks.data());
		xorBlock(data.data() + off, ks.data(), bs);
		incrementCounter(ctr.data(), bs);
	}
	if (off < data.size())
	{
		Block ks = ctr;
		encryptBlock(ks.data());
		xorBlock(data.data() + off, ks.data(), data.size() - off);
	}
}

void BlockCipher::decryptCTR(std::span<uint8_t> data, std::span<const uint8_t> iv) const
{
	requireKey();
	encryptCTR(data, iv);
}

/* Block modes pad before encryption. PKCS7, ANSIX923 and ISO78164 always add
   a block, even when the message is already aligned, so unpadding is
   unambiguous. Zeros only fills up to the next block boundary, matching the
   C and Python siblings: an aligned or empty message gets no extra block.
   None adds nothing. The keystream modes are length-preserving and ignore the
   padding argument. */
static bool needsPadding(BlockMode mode)
{
	return mode == BlockMode::ECB || mode == BlockMode::CBC || mode == BlockMode::PCBC;
}

/* ECB takes no IV; every chained mode takes exactly one block. A wrong-sized
   IV used to be silently truncated or zero-extended, which made a caller's
   mistake look like a successful encryption. */
void BlockCipher::validateIV(std::span<const uint8_t> iv, BlockMode mode) const
{
	if (mode == BlockMode::ECB)
	{
		if (!iv.empty())
			throw std::invalid_argument("ECB mode does not use an IV");
		return;
	}
	requireBlockIV(iv);
}

std::vector<uint8_t> BlockCipher::encryptMode(std::span<const uint8_t> plt, BlockMode mode,
		Padding padding, std::span<const uint8_t> iv) const
{
	requireKey();
	validateIV(iv, mode);

	std::vector<uint8_t> out(plt.begin(), plt.end());
	std::vector<uint8_t> chain(iv.begin(), iv.end());

	const size_t bs = blockSize();
	if (needsPadding(mode))
	{
		if (padding == Padding::None && out.size() % bs != 0)
			throw std::invalid_argument("Padding::None requires block-aligned input");
		const size_t missing = (padding == Padding::Zeros)
				? (bs - out.size() % bs) % bs
				: missingFor(out.size(), bs);
		pad(out, missing, padding);
	}
	if (out.empty())
		return out;

	switch (mode)
	{
		case BlockMode::ECB: encryptECB(out); break;
		case BlockMode::CBC: encryptCBC(out, chain); break;
		case BlockMode::PCBC: encryptPCBC(out, chain); break;
		case BlockMode::CFB: encryptCFB(out, chain); break;
		case BlockMode::OFB: encryptOFB(out, chain); break;
		case BlockMode::CTR: encryptCTR(out, chain); break;
	}
	return out;
}

std::vector<uint8_t> BlockCipher::decryptMode(std::span<const uint8_t> plt, BlockMode mode,
		Padding padding, std::span<const uint8_t> iv) const
{
	requireKey();
	validateIV(iv, mode);

	std::vector<uint8_t> out(plt.begin(), plt.end());
	std::vector<uint8_t> chain(iv.begin(), iv.end());

	const size_t bs = blockSize();
	if (out.empty())
	{
		/* No ciphertext is valid only when the scheme does not need a
		   padding block; a strict scheme must reject the empty message. */
		if (needsPadding(mode) && !unpad(out, padding, bs))
			throw std::invalid_argument("invalid padding");
		return out;
	}

	if (needsPadding(mode) && out.size() % bs != 0)
		throw std::invalid_argument("ciphertext is not block-aligned");

	switch (mode)
	{
		case BlockMode::ECB: decryptECB(out); break;
		case BlockMode::CBC: decryptCBC(out, chain); break;
		case BlockMode::PCBC: decryptPCBC(out, chain); break;
		case BlockMode::CFB: decryptCFB(out, chain); break;
		case BlockMode::OFB: decryptOFB(out, chain); break;
		case BlockMode::CTR: decryptCTR(out, chain); break;
	}
	if (needsPadding(mode) && !unpad(out, padding, bs))
		throw std::invalid_argument("invalid padding");
	return out;
}

static Padding filePadding(int p)
{
	switch (p)
	{
		case 0: return Padding::Zeros;
		case 2: return Padding::ANSIX923;
		case 3: return Padding::ISO78164;
		default: return Padding::PKCS7;
	}
}

static void encryptFileImpl(const BlockCipher &c, const std::string &path)
{
	std::ifstream input_file(path, std::ios::binary);
	std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
	input_file.close();
	const size_t bs = c.blockSize();
	const Padding p = filePadding(c.padding);
	const size_t m = (p == Padding::Zeros && vec.size() % bs == 0) ? 0 : missingFor(vec.size(), bs);
	pad(vec, m, p);
	if (!vec.empty())
	{
		if (c.mode == 1)
			c.encryptCBC(vec, std::vector<uint8_t>(bs, 0xff));
		else
			c.encryptECB(vec);
	}
	std::ofstream file(path);
	file.write(reinterpret_cast<const char*>(vec.data()), static_cast<std::streamsize>(vec.size()));
	file.close();
}

static void decryptFileImpl(const BlockCipher &c, const std::string &path)
{
	std::ifstream input_file(path, std::ios::binary);
	std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
	input_file.close();
	if (!vec.empty())
	{
		if (c.mode == 1)
		{
			std::vector<uint8_t> iv(c.blockSize(), 0xff);
			c.decryptCBC(vec, iv);
		}
		else
			c.decryptECB(vec);
	}
	(void) unpad(vec, filePadding(c.padding), c.blockSize());
	std::ofstream file(path);
	file.write(reinterpret_cast<const char*>(vec.data()), static_cast<std::streamsize>(vec.size()));
	file.close();
}

void BlockCipher::encrypt_File(char* path) const
{
	requireKey();
	encryptFileImpl(*this, path);
}

void BlockCipher::encrypt_FileS(std::string path) const
{
	requireKey();
	encryptFileImpl(*this, path);
}

void BlockCipher::decrypt_File(char* path) const
{
	requireKey();
	decryptFileImpl(*this, path);
}

} // namespace block
