#ifndef TWIFISH_HEADER
#define TWIFISH_HEADER

#include <stdint.h>
#include <vector>
#include <string>

#include "BlockCipher.h"

class Twofish : public BlockCipher{
public:
	Twofish();
	std::vector<std::vector<uint8_t>> RS;

	std::vector<std::vector<uint8_t>> MDS;
	std::vector<uint8_t> MDSEF;
	std::vector<uint8_t> MDS5B;
	
	std::vector<uint8_t> q0;
	std::vector<uint8_t> q1;


	std::vector<uint32_t> Sbox0;
	std::vector<uint32_t> Sbox1;
	std::vector<uint32_t> Sbox2;
	std::vector<uint32_t> Sbox3;

	std::vector<uint32_t> Subkeys;

	
	uint32_t multgf(uint32_t a,uint32_t b,uint32_t pol) const;

	uint8_t multgf(uint16_t a,uint16_t b) const;
	
	uint8_t RSAmul(int i, const uint8_t *p) const;

	void generateKeys(const std::vector<uint8_t>& key);

	void encrypt_block(uint8_t *lb0,uint8_t *lb1,uint8_t *rb0,uint8_t *rb1) const;

	void decrypt_block(uint8_t *lb0,uint8_t *lb1,uint8_t *rb0,uint8_t *rb1) const;
	
	int blockSize() const;

	void encryptBlock(uint8_t *block) const;

	void decryptBlock(uint8_t *block) const;

	std::vector<uint8_t> encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const;

};

#endif
