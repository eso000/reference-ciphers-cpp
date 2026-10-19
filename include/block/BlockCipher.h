#ifndef BLOCKCIPHER_HEADER
#define BLOCKCIPHER_HEADER

#include <stdint.h>
#include <vector>
#include <string>

#include "block/Padding.h"

/* The helpers below are called from hot inner loops, so they must keep the
   always_inline binding that force_inline.h documents: a plain `inline` hint
   is declined for the larger round helpers at -O2 by gcc, which cost AES and
   Serpent about 30% of their speed. A static member cannot reuse FORCE_INLINE
   (its leading `static` already means "no this"), so the attribute is spelled
   out here. */
#if defined(__GNUC__)
#define BLOCKCIPHER_INLINE inline __attribute__((always_inline))
#else
#define BLOCKCIPHER_INLINE inline
#endif

enum class BlockMode { ECB, CBC, PCBC, CFB, OFB, CTR };

class BlockCipher {
public:
	/* Shared bit and endian helpers. These used to be copied into AES,
	   Blowfish, Serpent and Twofish; they live here so there is one copy.
	   They are public because the round helpers in those files are free
	   functions, which cannot reach protected members. */
	BLOCKCIPHER_INLINE static uint8_t byte0(uint32_t x) { return (uint8_t)(x >> 24); }
	BLOCKCIPHER_INLINE static uint8_t byte1(uint32_t x) { return (uint8_t)(x >> 16); }
	BLOCKCIPHER_INLINE static uint8_t byte2(uint32_t x) { return (uint8_t)(x >> 8); }
	BLOCKCIPHER_INLINE static uint8_t byte3(uint32_t x) { return (uint8_t)x; }

	BLOCKCIPHER_INLINE static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
	BLOCKCIPHER_INLINE static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

	BLOCKCIPHER_INLINE static uint32_t load32_be(const uint8_t *p)
	{
		return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
	}

	BLOCKCIPHER_INLINE static void store32_be(uint8_t *p, uint32_t w)
	{
		p[0] = byte0(w);
		p[1] = byte1(w);
		p[2] = byte2(w);
		p[3] = byte3(w);
	}

	BLOCKCIPHER_INLINE static uint32_t load32_le(const uint8_t *p)
	{
		return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	}

	BLOCKCIPHER_INLINE static void store32_le(uint8_t *p, uint32_t w)
	{
		p[0] = byte3(w);
		p[1] = byte2(w);
		p[2] = byte1(w);
		p[3] = byte0(w);
	}

	virtual ~BlockCipher() {}

	int mode = 0;

	int padding = 1;

	virtual int blockSize() const = 0;

	virtual void encryptBlock(uint8_t *block) const = 0;

	virtual void decryptBlock(uint8_t *block) const = 0;

	void encryptECB(uint8_t *plt, int len) const;

	void decryptECB(uint8_t *plt, int len) const;

	void encryptCBC(uint8_t *plt, int len, uint8_t *iv) const;

	void decryptCBC(uint8_t *plt, int len, uint8_t *iv) const;

	void encryptPCBC(uint8_t *plt, int len, uint8_t *iv) const;

	void decryptPCBC(uint8_t *plt, int len, uint8_t *iv) const;

	void encryptCFB(uint8_t *plt, int len, uint8_t *iv) const;

	void decryptCFB(uint8_t *plt, int len, uint8_t *iv) const;

	void encryptOFB(uint8_t *plt, int len, uint8_t *iv) const;

	void decryptOFB(uint8_t *plt, int len, uint8_t *iv) const;

	void encryptCTR(uint8_t *plt, int len, uint8_t *iv) const;

	void decryptCTR(uint8_t *plt, int len, uint8_t *iv) const;

	std::vector<uint8_t> encryptMode(std::vector<uint8_t> plt, BlockMode mode,
			Padding padding, std::vector<uint8_t> iv = std::vector<uint8_t>()) const;

	std::vector<uint8_t> decryptMode(std::vector<uint8_t> plt, BlockMode mode,
			Padding padding, std::vector<uint8_t> iv = std::vector<uint8_t>()) const;

	void encrypt_File(char* path) const;

	void encrypt_FileS(std::string path) const;

	void decrypt_File(char* path) const;

private:
	std::vector<uint8_t> normalizeIV(std::vector<uint8_t> iv) const;
};

#endif
