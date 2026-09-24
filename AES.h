#ifndef AES_HEADER
#define AES_HEADER


#include <stdint.h>
#include <vector>
#include <string>

#include "BlockCipher.h"


class AES : public BlockCipher{
public:
	AES();

	std::vector<uint8_t> SBoxes;
	std::vector<uint8_t> InvSBoxes;

	std::vector<uint8_t> GF2;
	std::vector<uint8_t> GF3;
	std::vector<uint8_t> GF9;
	std::vector<uint8_t> GF11;
	std::vector<uint8_t> GF13;
	std::vector<uint8_t> GF14;

	std::vector<uint32_t> MixRowCol0;
	std::vector<uint32_t> MixRowCol1;
	std::vector<uint32_t> MixRowCol2;
	std::vector<uint32_t> MixRowCol3;

	std::vector<uint32_t> invMixRowCol0;
	std::vector<uint32_t> invMixRowCol1;
	std::vector<uint32_t> invMixRowCol2;
	std::vector<uint32_t> invMixRowCol3;


	std::vector<uint32_t> Subkeys;

	uint8_t GFMult(int i, uint8_t s) const;

	void generateKeys(std::string key);

	void encrypt_block128(uint8_t *p) const;

	void encrypt_block192(uint8_t *p) const;

	void encrypt_block256(uint8_t *p) const;

	void decrypt_block128(uint8_t *p) const;

	void decrypt_block192(uint8_t *p) const;

	void decrypt_block256(uint8_t *p) const;

	int blockSize() const;

	void encryptBlock(uint8_t *block) const;

	void decryptBlock(uint8_t *block) const;

	void encrypt(uint8_t *plt, int len) const;
	
	std::vector<uint8_t> encrypt(std::vector<uint8_t> plt) const;

	void decrypt(uint8_t *plt, int len) const;

	std::vector<uint8_t> decrypt(std::vector<uint8_t> plt) const;

	
};


#endif
