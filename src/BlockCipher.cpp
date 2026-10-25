#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "block/BlockCipher.h"

static void xorBlock(uint8_t *dst, const uint8_t *src, int n)
{
	for (int i = 0; i < n; ++i)
		dst[i] ^= src[i];
}

static void incrementCounter(uint8_t *ctr, int n)
{
	for (int i = n - 1; i >= 0; --i)
		if (++ctr[i] != 0)
			break;
}

void BlockCipher::requireKey() const
{
	if (!keySet)
		throw std::logic_error("key schedule is not initialized; call generateKeys first");
}

void BlockCipher::encryptECB(uint8_t *plt, int len) const
{
	requireKey();
	int bs = blockSize();
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
		encryptBlock(i);
}

void BlockCipher::decryptECB(uint8_t *plt, int len) const
{
	requireKey();
	int bs = blockSize();
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
		decryptBlock(i);
}

void BlockCipher::encryptCBC(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		xorBlock(i, iv, bs);
		encryptBlock(i);
		iv = i;
	}
}

void BlockCipher::decryptCBC(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t t[16];
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(t, i, bs);
		decryptBlock(i);
		xorBlock(i, iv, bs);
		memcpy(iv, t, bs);
	}
}

void BlockCipher::encryptPCBC(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t t[16];
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(t, i, bs);
		xorBlock(i, iv, bs);
		encryptBlock(i);
		xorBlock(t, i, bs);
		memcpy(iv, t, bs);
	}
}

void BlockCipher::decryptPCBC(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t t[16];
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(t, i, bs);
		decryptBlock(i);
		xorBlock(i, iv, bs);
		xorBlock(t, i, bs);
		memcpy(iv, t, bs);
	}
}

/* The keystream modes can take a short final block: the cipher is run once
   more and only the bytes that remain are XORed. The feedback value that
   would follow the truncated block is never used, so it does not have to be
   computed or padded. */
void BlockCipher::encryptCFB(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t reg[16];
	uint8_t *i = plt;
	uint8_t *end = plt + len;
	memcpy(reg, iv, bs);
	for (; end - i >= bs; i += bs)
	{
		encryptBlock(reg);
		xorBlock(i, reg, bs);
		memcpy(reg, i, bs);
	}
	if (i < end)
	{
		encryptBlock(reg);
		xorBlock(i, reg, (int) (end - i));
	}
}

void BlockCipher::decryptCFB(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t reg[16];
	uint8_t t[16];
	uint8_t *i = plt;
	uint8_t *end = plt + len;
	memcpy(reg, iv, bs);
	for (; end - i >= bs; i += bs)
	{
		encryptBlock(reg);
		memcpy(t, i, bs);
		xorBlock(i, reg, bs);
		memcpy(reg, t, bs);
	}
	if (i < end)
	{
		encryptBlock(reg);
		xorBlock(i, reg, (int) (end - i));
	}
}

void BlockCipher::encryptOFB(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t reg[16];
	uint8_t *i = plt;
	uint8_t *end = plt + len;
	memcpy(reg, iv, bs);
	for (; end - i >= bs; i += bs)
	{
		encryptBlock(reg);
		xorBlock(i, reg, bs);
	}
	if (i < end)
	{
		encryptBlock(reg);
		xorBlock(i, reg, (int) (end - i));
	}
}

void BlockCipher::decryptOFB(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	encryptOFB(plt, len, iv);
}

void BlockCipher::encryptCTR(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	int bs = blockSize();
	uint8_t ctr[16];
	uint8_t ks[16];
	uint8_t *i = plt;
	uint8_t *end = plt + len;
	memcpy(ctr, iv, bs);
	for (; end - i >= bs; i += bs)
	{
		memcpy(ks, ctr, bs);
		encryptBlock(ks);
		xorBlock(i, ks, bs);
		incrementCounter(ctr, bs);
	}
	if (i < end)
	{
		memcpy(ks, ctr, bs);
		encryptBlock(ks);
		xorBlock(i, ks, (int) (end - i));
	}
}

void BlockCipher::decryptCTR(uint8_t *plt, int len, uint8_t *iv) const
{
	requireKey();
	encryptCTR(plt, len, iv);
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
void BlockCipher::validateIV(const std::vector<uint8_t> &iv, BlockMode mode) const
{
	if (mode == BlockMode::ECB)
	{
		if (!iv.empty())
			throw std::invalid_argument("ECB mode does not use an IV");
		return;
	}
	if ((int) iv.size() != blockSize())
		throw std::invalid_argument("IV must be exactly " + std::to_string(blockSize())
				+ " bytes, got " + std::to_string(iv.size()));
}

std::vector<uint8_t> BlockCipher::encryptMode(std::vector<uint8_t> plt, BlockMode mode,
		Padding padding, std::vector<uint8_t> iv) const
{
	requireKey();
	validateIV(iv, mode);

	int bs = blockSize();
	if (needsPadding(mode))
	{
		if (padding == Padding::None && (int) plt.size() % bs != 0)
			throw std::invalid_argument("Padding::None requires block-aligned input");
		int missing = (padding == Padding::Zeros)
				? (bs - (int) plt.size() % bs) % bs
				: missingFor((int) plt.size(), bs);
		pad(plt, missing, padding);
	}
	if (plt.empty())
		return plt;

	switch (mode)
	{
		case BlockMode::ECB: encryptECB(&plt[0], (int) plt.size()); break;
		case BlockMode::CBC: encryptCBC(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::PCBC: encryptPCBC(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::CFB: encryptCFB(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::OFB: encryptOFB(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::CTR: encryptCTR(&plt[0], (int) plt.size(), &iv[0]); break;
	}
	return plt;
}

std::vector<uint8_t> BlockCipher::decryptMode(std::vector<uint8_t> plt, BlockMode mode,
		Padding padding, std::vector<uint8_t> iv) const
{
	requireKey();
	validateIV(iv, mode);

	int bs = blockSize();
	if (plt.empty())
	{
		/* No ciphertext is valid only when the scheme does not need a
		   padding block; a strict scheme must reject the empty message. */
		if (needsPadding(mode) && !unpad(plt, padding, bs))
			throw std::invalid_argument("invalid padding");
		return plt;
	}

	if (needsPadding(mode) && (int) plt.size() % bs != 0)
		throw std::invalid_argument("ciphertext is not block-aligned");

	switch (mode)
	{
		case BlockMode::ECB: decryptECB(&plt[0], (int) plt.size()); break;
		case BlockMode::CBC: decryptCBC(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::PCBC: decryptPCBC(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::CFB: decryptCFB(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::OFB: decryptOFB(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::CTR: decryptCTR(&plt[0], (int) plt.size(), &iv[0]); break;
	}
	if (needsPadding(mode) && !unpad(plt, padding, bs))
		throw std::invalid_argument("invalid padding");
	return plt;
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
	int bs = c.blockSize();
	int l = (int) vec.size();
	Padding p = filePadding(c.padding);
	int m = (p == Padding::Zeros && l % bs == 0) ? 0 : missingFor(l, bs);
	if (m)
		pad(vec, m, p);
	if (!vec.empty())
	{
		if (c.mode == 1)
		{
			uint8_t iv[16];
			memset(iv, 0xff, bs);
			c.encryptCBC(&vec[0], (int) vec.size(), iv);
		}
		else
			c.encryptECB(&vec[0], (int) vec.size());
	}
	std::ofstream file(path);
	if (!vec.empty())
		file.write(reinterpret_cast<char*>(&vec[0]), vec.size());
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
			uint8_t iv[16];
			memset(iv, 0xff, c.blockSize());
			c.decryptCBC(&vec[0], (int) vec.size(), iv);
		}
		else
			c.decryptECB(&vec[0], (int) vec.size());
	}
	(void) unpad(vec, filePadding(c.padding), c.blockSize());
	std::ofstream file(path);
	if (!vec.empty())
		file.write(reinterpret_cast<char*>(&vec[0]), vec.size());
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
