#ifndef BLOWFISH_HEADER
#define BLOWFISH_HEADER

#include <stdint.h>
#include <vector>

class Blowfish{
public:
	
	
	std::vector<uint32_t> SBoxes0;
	std::vector<uint32_t> SBoxes1;
	std::vector<uint32_t> SBoxes2;
	std::vector<uint32_t> SBoxes3;
	std::vector<uint32_t> Subkeys;
	
	

	void encrypt_block(uint8_t *lb,uint8_t *rb) const;

	void decrypt_block(uint8_t *lb,uint8_t *rb) const;

	void generateKeys(const std::vector<uint8_t>& key);
	
	void encryptECB(uint8_t *plt, int len) const;

	void decryptECB(uint8_t *plt, int len) const;

	void encryptCBC(uint8_t *plt, int len, uint8_t *iv) const;

	void encryptPCBC(uint8_t *plt, int len, uint8_t *iv) const;

	void encryptCFB(uint8_t *plt, int len, uint8_t *iv) const;

	std::vector<uint8_t> encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const;
	
	void encrypt_File(char* path) const;

	void decrypt_File(char* path) const;

};

#endif
