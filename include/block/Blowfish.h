#ifndef BLOWFISH_HEADER
#define BLOWFISH_HEADER

#include <stdint.h>
#include <vector>

#include "block/BlockCipher.h"

class Blowfish : public BlockCipher{
public:
	
	
	std::vector<uint32_t> SBoxes0;
	std::vector<uint32_t> SBoxes1;
	std::vector<uint32_t> SBoxes2;
	std::vector<uint32_t> SBoxes3;
	std::vector<uint32_t> Subkeys;
	
	

	void generateKeys(const std::vector<uint8_t>& key);
	
	int blockSize() const;

	void encryptBlock(uint8_t *block) const;

	void decryptBlock(uint8_t *block) const;

	std::vector<uint8_t> encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const;

};

#endif
