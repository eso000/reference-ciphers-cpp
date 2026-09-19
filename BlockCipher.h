#ifndef BLOCKCIPHER_HEADER
#define BLOCKCIPHER_HEADER

#include <stdint.h>
#include <vector>
#include <string>

#include "Padding.h"

enum class BlockMode { ECB, CBC, PCBC, CFB, OFB, CTR };

class BlockCipher {
public:
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
