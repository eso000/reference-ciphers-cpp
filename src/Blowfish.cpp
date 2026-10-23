#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "block/Blowfish.h"
#include <iterator>
#include "Blowfish_data.h"
#include "force_inline.h"

FORCE_INLINE uint32_t blowfish_F(const Blowfish *bf, uint32_t x)
{
	return ((bf->SBoxes0[BlockCipher::byte0(x)] + bf->SBoxes1[BlockCipher::byte1(x)]) ^ bf->SBoxes2[BlockCipher::byte2(x)]) + bf->SBoxes3[BlockCipher::byte3(x)];
}

FORCE_INLINE void blowfish_round(uint32_t *l, uint32_t *r, int i, const Blowfish *bf)
{
	*l ^= bf->Subkeys[i];
	*r ^= blowfish_F(bf, *l);
}

	void Blowfish::encryptBlock(uint8_t *block) const
	{
		uint32_t left = BlockCipher::load32_be(block);
		uint32_t right = BlockCipher::load32_be(block + 4);

		blowfish_round(&left, &right, 0, this);  blowfish_round(&right, &left, 1, this);
		blowfish_round(&left, &right, 2, this);  blowfish_round(&right, &left, 3, this);
		blowfish_round(&left, &right, 4, this);  blowfish_round(&right, &left, 5, this);
		blowfish_round(&left, &right, 6, this);  blowfish_round(&right, &left, 7, this);
		blowfish_round(&left, &right, 8, this);  blowfish_round(&right, &left, 9, this);
		blowfish_round(&left, &right, 10, this); blowfish_round(&right, &left, 11, this);
		blowfish_round(&left, &right, 12, this); blowfish_round(&right, &left, 13, this);
		blowfish_round(&left, &right, 14, this); blowfish_round(&right, &left, 15, this);
		left ^= Subkeys[16];
		right ^= Subkeys[17];

		BlockCipher::store32_be(block + 4, left);
		BlockCipher::store32_be(block, right);
	}


	void Blowfish::decryptBlock(uint8_t *block) const
	{
		uint32_t left = BlockCipher::load32_be(block);
		uint32_t right = BlockCipher::load32_be(block + 4);

		blowfish_round(&left, &right, 17, this); blowfish_round(&right, &left, 16, this);
		blowfish_round(&left, &right, 15, this); blowfish_round(&right, &left, 14, this);
		blowfish_round(&left, &right, 13, this); blowfish_round(&right, &left, 12, this);
		blowfish_round(&left, &right, 11, this); blowfish_round(&right, &left, 10, this);
		blowfish_round(&left, &right, 9, this);  blowfish_round(&right, &left, 8, this);
		blowfish_round(&left, &right, 7, this);  blowfish_round(&right, &left, 6, this);
		blowfish_round(&left, &right, 5, this);  blowfish_round(&right, &left, 4, this);
		blowfish_round(&left, &right, 3, this);  blowfish_round(&right, &left, 2, this);
		left ^= Subkeys[1];
		right ^= Subkeys[0];

		BlockCipher::store32_be(block + 4, left);
		BlockCipher::store32_be(block, right);
	}


	
	void Blowfish::generateKeys(const std::vector<uint8_t>& key){
		/* Blowfish's published key schedule covers 1- to 24-byte keys, so the lower
		   bound stays at 1: Schneier's own set_key vectors for the 1, 2 and
		   3-byte cases are part of the definition and this implementation
		   computes them. Python rejects those three lengths and so cannot
		   reproduce those vectors. The upper bound is 56 bytes, from the
		   cipher's 448-bit maximum. */
		if (key.empty() || key.size() > 56)
			throw std::invalid_argument("Blowfish key must be 1 to 56 bytes, got " + std::to_string(key.size()));
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

		for(int i=0;i <(int)Subkeys.size(); i=i+2){
			encryptBlock(P);
			Subkeys[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			Subkeys[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<(int)SBoxes0.size();i=i+2){
			encryptBlock(P);
			SBoxes0[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes0[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<(int)SBoxes1.size();i=i+2){
			encryptBlock(P);
			SBoxes1[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes1[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<(int)SBoxes2.size();i=i+2){
			encryptBlock(P);
			SBoxes2[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes2[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
		for(int i = 0 ;i<(int)SBoxes3.size();i=i+2){
			encryptBlock(P);
			SBoxes3[i] = ((uint32_t)P[0]<<24) + ((uint32_t)P[1]<<16) + ((uint32_t)P[2]<<8) + P[3];
			SBoxes3[i+1] = ((uint32_t)P[4]<<24) + ((uint32_t)P[5]<<16) + ((uint32_t)P[6]<<8) + P[7];
		}
	}	
	
	int Blowfish::blockSize() const
	{
		return 8;
	}

	std::vector<uint8_t> Blowfish::encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const
	{
		(void) iv;
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}
