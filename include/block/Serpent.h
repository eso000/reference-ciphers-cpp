#ifndef SERPENT_HEADER
#define SERPENT_HEADER

#include <stdint.h>
#include <vector>
#include <string>

#include "block/BlockCipher.h"

class Serpent : public BlockCipher{
public:
	Serpent();

	std::vector<std::vector<uint8_t>> SBox;
  std::vector<std::vector<uint8_t>> invSBox;

	std::vector<uint32_t> Subkeys;

	void applySBox(uint32_t *x0,uint32_t *x1,uint32_t *x2, uint32_t *x3, int n) const;

	void applyInvSBox(uint32_t *x0,uint32_t *x1,uint32_t *x2, uint32_t *x3, int n) const;

	void generateKeys(std::string key);

	void encrypt_block(uint8_t *x0,uint8_t *x1,uint8_t *x2,uint8_t *x3) const;

	void decrypt_block(uint8_t *x0,uint8_t *x1,uint8_t *x2,uint8_t *x3) const;

	int blockSize() const;

	void encryptBlock(uint8_t *block) const;

	void decryptBlock(uint8_t *block) const;

	std::vector<uint8_t> encrypt(std::vector<uint8_t> plt) const;

	std::vector<uint8_t> decrypt(std::vector<uint8_t> plt) const;

};

#endif
