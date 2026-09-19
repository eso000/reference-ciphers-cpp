#include <cstring>
#include <fstream>
#include <iterator>

#include "BlockCipher.h"

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

void BlockCipher::encryptECB(uint8_t *plt, int len) const
{
	int bs = blockSize();
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
		encryptBlock(i);
}

void BlockCipher::decryptECB(uint8_t *plt, int len) const
{
	int bs = blockSize();
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
		decryptBlock(i);
}

void BlockCipher::encryptCBC(uint8_t *plt, int len, uint8_t *iv) const
{
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

void BlockCipher::encryptCFB(uint8_t *plt, int len, uint8_t *iv) const
{
	int bs = blockSize();
	uint8_t reg[16];
	memcpy(reg, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		encryptBlock(reg);
		xorBlock(i, reg, bs);
		memcpy(reg, i, bs);
	}
}

void BlockCipher::decryptCFB(uint8_t *plt, int len, uint8_t *iv) const
{
	int bs = blockSize();
	uint8_t reg[16];
	uint8_t t[16];
	memcpy(reg, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		encryptBlock(reg);
		memcpy(t, i, bs);
		xorBlock(i, reg, bs);
		memcpy(reg, t, bs);
	}
}

void BlockCipher::encryptOFB(uint8_t *plt, int len, uint8_t *iv) const
{
	int bs = blockSize();
	uint8_t reg[16];
	memcpy(reg, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		encryptBlock(reg);
		xorBlock(i, reg, bs);
	}
}

void BlockCipher::decryptOFB(uint8_t *plt, int len, uint8_t *iv) const
{
	encryptOFB(plt, len, iv);
}

void BlockCipher::encryptCTR(uint8_t *plt, int len, uint8_t *iv) const
{
	int bs = blockSize();
	uint8_t ctr[16];
	uint8_t ks[16];
	memcpy(ctr, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(ks, ctr, bs);
		encryptBlock(ks);
		xorBlock(i, ks, bs);
		incrementCounter(ctr, bs);
	}
}

void BlockCipher::decryptCTR(uint8_t *plt, int len, uint8_t *iv) const
{
	encryptCTR(plt, len, iv);
}

std::vector<uint8_t> BlockCipher::normalizeIV(std::vector<uint8_t> iv) const
{
	int bs = blockSize();
	if ((int) iv.size() > bs)
		iv.resize(bs);
	else
		iv.resize(bs, (uint8_t) 0);
	return iv;
}

std::vector<uint8_t> BlockCipher::encryptMode(std::vector<uint8_t> plt, BlockMode mode,
		Padding padding, std::vector<uint8_t> iv) const
{
	int bs = blockSize();
	pad(plt, missingFor((int) plt.size(), bs), padding);
	if (plt.empty())
		return plt;

	iv = normalizeIV(iv);
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
	if (plt.empty())
		return plt;

	int bs = blockSize();
	iv = normalizeIV(iv);
	switch (mode)
	{
		case BlockMode::ECB: decryptECB(&plt[0], (int) plt.size()); break;
		case BlockMode::CBC: decryptCBC(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::PCBC: decryptPCBC(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::CFB: decryptCFB(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::OFB: decryptOFB(&plt[0], (int) plt.size(), &iv[0]); break;
		case BlockMode::CTR: decryptCTR(&plt[0], (int) plt.size(), &iv[0]); break;
	}
	unpad(plt, padding, bs);
	return plt;
}

void BlockCipher::encrypt_File(char* path) const
{
	std::ifstream input_file(path, std::ios::binary);
	std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
	input_file.close();
	vec = encryptMode(vec, BlockMode::ECB, Padding::PKCS7);
	std::ofstream file(path);
	if (!vec.empty())
		file.write(reinterpret_cast<char*>(&vec[0]), vec.size());
	file.close();
}

void BlockCipher::decrypt_File(char* path) const
{
	std::ifstream input_file(path, std::ios::binary);
	std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
	input_file.close();
	vec = decryptMode(vec, BlockMode::ECB, Padding::PKCS7);
	std::ofstream file(path);
	if (!vec.empty())
		file.write(reinterpret_cast<char*>(&vec[0]), vec.size());
	file.close();
}
