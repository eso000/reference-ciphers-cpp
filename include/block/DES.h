#ifndef DES_HEADER
#define DES_HEADER

#include <stdint.h>
#include <vector>
#include <string>

#include "block/BlockCipher.h"

class DES : public BlockCipher{
public:

	DES(bool useAlt = true);

	bool use_alt;

	std::vector<uint8_t> initialperm;
	std::vector<uint8_t> inverseperm;
	std::vector<uint8_t> ExpentionPerm;
	std::vector<uint8_t> SBoxes0;
	std::vector<uint8_t> SBoxes1;
	std::vector<uint8_t> SBoxes2;
	std::vector<uint8_t> SBoxes3;
	std::vector<uint8_t> SBoxes4;
	std::vector<uint8_t> SBoxes5;
	std::vector<uint8_t> SBoxes6;
	std::vector<uint8_t> SBoxes7;


	std::vector<uint8_t> keyperm1;
	std::vector<uint8_t> keyperm2;
	std::vector<uint8_t> PBox;

	std::vector<uint64_t> Subkeys;

	uint64_t permutate(uint64_t x, std::vector<uint8_t> P, int base_size) const;

	static uint64_t ip_perm_alt(uint64_t block);

	static uint64_t fp_perm_alt(uint64_t block);

	void generateKeys(std::string key);

	void encrypt_block(uint8_t *lb,uint8_t *rb) const;

	void decrypt_block(uint8_t *lb,uint8_t *rb) const;

	int blockSize() const;

	void encryptBlock(uint8_t *block) const;

	void decryptBlock(uint8_t *block) const;

	std::vector<uint8_t> encrypt(std::vector<uint8_t> plt) const;

	std::vector<uint8_t> decrypt(std::vector<uint8_t> plt) const;

};

#endif
