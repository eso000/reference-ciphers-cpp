#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "Blowfish.h"
#include <iterator>
#include "Blowfish_data.h"



#define byte0(x) (uint8_t)(x>>24)
#define byte1(x) (uint8_t)(x>>16)
#define byte2(x) (uint8_t)(x>>8)
#define byte3(x) (uint8_t)x

#define S(i,n) SBoxes##i[byte##i(n)]
#define F(x) (( ( S(0,x)+ S(1,x))^S(2,x)) + S(3,x))
#define round(l,r,i) l ^= Subkeys[i]; r ^= F(l);

	

	void Blowfish::encrypt_block(uint8_t *lb,uint8_t *rb) const
	{
		uint32_t left, right;
		left = ((uint32_t)*lb<<24)| ((uint32_t)*(lb+1)<<16)|((uint32_t)*(lb+2)<<8)|*(lb+3);
		right = ((uint32_t)*rb<<24)| ((uint32_t)*(rb+1)<<16)|((uint32_t)*(rb+2)<<8)|*(rb+3);

		round (left, right, 0) ;  round (right, left, 1) ;
		round (left, right, 2) ;  round (right, left, 3) ;
		round (left, right, 4) ;  round (right, left, 5) ;
		round (left, right, 6) ;  round (right, left, 7) ;
		round (left, right, 8) ;  round (right, left, 9) ;
		round (left, right, 10) ; round (right, left, 11) ;
		round (left, right, 12) ; round (right, left, 13) ;
		round (left, right, 14) ; round (right, left, 15) ;
		left ^= Subkeys[16];
		right ^= Subkeys[17];

		*rb = byte0(left); *(rb+1) = byte1(left); *(rb+2) = byte2(left); *(rb+3) = byte3(left);
		*lb = byte0(right); *(lb+1) = byte1(right); *(lb+2) = byte2(right); *(lb+3) = byte3(right);
	}


	void Blowfish::decrypt_block(uint8_t *lb,uint8_t *rb) const
	{
		uint32_t left, right;
		left = ((uint32_t)*lb<<24)| ((uint32_t)*(lb+1)<<16)|((uint32_t)*(lb+2)<<8)|*(lb+3);
		right = ((uint32_t)*rb<<24)| ((uint32_t)*(rb+1)<<16)|((uint32_t)*(rb+2)<<8)|*(rb+3);

		
		round (left, right, 17); round (right, left, 16);
		round (left, right, 15); round (right, left, 14);
		round (left, right, 13); round (right, left, 12);
		round (left, right, 11); round (right, left, 10);
		round (left, right, 9) ; round (right, left, 8) ;
		round (left, right, 7) ; round (right, left, 6) ;
		round (left, right, 5) ; round (right, left, 4) ;
		round (left, right, 3) ; round (right, left, 2) ;
		left ^= Subkeys[1];
		right ^= Subkeys[0];

		*rb = byte0(left); *(rb+1) = byte1(left); *(rb+2) = byte2(left); *(rb+3) = byte3(left);
		*lb = byte0(right); *(lb+1) = byte1(right); *(lb+2) = byte2(right); *(lb+3) = byte3(right);
	}


	
	void Blowfish::generateKeys(const std::vector<uint8_t>& key){
		if (key.empty() || key.size() > 56)
			throw std::invalid_argument("Blowfish key must be 1..56 bytes");
		std::vector<uint32_t> PBox(std::begin(PBox_data), std::end(PBox_data));
		Subkeys.clear();
		for (int i = 0; i < 18; ++i) {
			size_t o = (size_t)(4 * i) % key.size();
			uint32_t w = ((uint32_t)key[o] << 24)
			           | ((uint32_t)key[(o+1) % key.size()] << 16)
			           | ((uint32_t)key[(o+2) % key.size()] << 8)
			           | (uint32_t)key[(o+3) % key.size()];
			Subkeys.push_back(PBox[i] ^ w);
		}

		std::vector<std::vector<uint32_t>> SBox;
		for (const auto& row : SBox_data) SBox.emplace_back(std::begin(row), std::end(row));
		SBoxes0 = SBox[0];
		SBoxes1 = SBox[1];
		SBoxes2 = SBox[2];
		SBoxes3 = SBox[3];

		uint8_t P[8] = {(uint8_t)0, (uint8_t)0, (uint8_t)0, (uint8_t)0,(uint8_t)0,(uint8_t)0,(uint8_t)0,(uint8_t)0};

		for(int i=0;i <Subkeys.size(); i=i+2){
			encrypt_block(&P[0], &P[4]);
			Subkeys[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			Subkeys[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<SBoxes0.size();i=i+2){
			encrypt_block(&P[0], &P[4]);
			SBoxes0[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes0[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<SBoxes1.size();i=i+2){
			encrypt_block(&P[0], &P[4]);
			SBoxes1[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes1[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<SBoxes2.size();i=i+2){
			encrypt_block(&P[0], &P[4]);
			SBoxes2[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes2[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<SBoxes3.size();i=i+2){
			encrypt_block(&P[0], &P[4]);
			SBoxes3[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes3[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
	}	
	
	int Blowfish::blockSize() const
	{
		return 8;
	}

	void Blowfish::encryptBlock(uint8_t *block) const
	{
		encrypt_block(block, block + 4);
	}

	void Blowfish::decryptBlock(uint8_t *block) const
	{
		decrypt_block(block, block + 4);
	}

	std::vector<uint8_t> Blowfish::encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const
	{
		(void) iv;
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}
