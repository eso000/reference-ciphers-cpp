
#include <math.h>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#include <fstream>
#include <sstream>

#include <chrono>
#include <thread>

#include "AES.h"



#define rotl4(arr1) t = arr1[0];\
			arr1[0] = arr1[1];\
			arr1[1] = arr1[2];\
			arr1[2] = arr1[3];\
			arr1[3] = t;


#define xor4(arr1, arr2) arr1[0] ^= arr2[0];\
	arr1[1] ^= arr2[1];\
	arr1[2] ^= arr2[2];\
	arr1[3] ^= arr2[3];

#define xor16(arr1, arr2) arr1[0] ^= *arr2;\
	arr1[1] ^= *(arr2+1);\
	arr1[2] ^= *(arr2+2);\
	arr1[3] ^= *(arr2+3);\
	arr1[4] ^= *(arr2+4);\
	arr1[5] ^= *(arr2+5);\
	arr1[6] ^= *(arr2+6);\
	arr1[7] ^= *(arr2+7);\
	arr1[8] ^= *(arr2+8);\
	arr1[9] ^= *(arr2+9);\
	arr1[10] ^= *(arr2+10);\
	arr1[11] ^= *(arr2+11);\
	arr1[12] ^= *(arr2+12);\
	arr1[13] ^= *(arr2+13);\
	arr1[14] ^= *(arr2+14);\
	arr1[15] ^= *(arr2+15);


#define byte0(x) (uint8_t)(x>>24)
#define byte1(x) (uint8_t)(x>>16)
#define byte2(x) (uint8_t)(x>>8)
#define byte3(x) (uint8_t)x


#define SubBites4(arr1) arr1[0] = SBoxes[arr1[0]];\
						arr1[1] = SBoxes[arr1[1]];\
						arr1[2] = SBoxes[arr1[2]];\
						arr1[3] = SBoxes[arr1[3]];

#define SB(id) SBoxes[(id)]

#define iSB(id) InvSBoxes[(id)]


#define SubBites(arr1)  arr1[0] = SBoxes[arr1[0]];\
						arr1[1] = SBoxes[arr1[1]];\
						arr1[2] = SBoxes[arr1[2]];\
						arr1[3] = SBoxes[arr1[3]];\
						arr1[4] = SBoxes[arr1[4]];\
						arr1[5] = SBoxes[arr1[5]];\
						arr1[6] = SBoxes[arr1[6]];\
						arr1[7] = SBoxes[arr1[7]];\
						arr1[8] = SBoxes[arr1[8]];\
						arr1[9] = SBoxes[arr1[9]];\
						arr1[10] = SBoxes[arr1[10]];\
						arr1[11] = SBoxes[arr1[11]];\
						arr1[12] = SBoxes[arr1[12]];\
						arr1[13] = SBoxes[arr1[13]];\
						arr1[14] = SBoxes[arr1[14]];\
						arr1[15] = SBoxes[arr1[15]];

#define ShiftRows(arr1) temp[0] = arr1[1];\
						temp[1] = arr1[2]; temp[2] = arr1[6];\
						temp[3] = arr1[15];\
						arr1[1] = arr1[5];\
						arr1[5] = arr1[9];\
						arr1[9] = arr1[13];\
						arr1[13] = temp[0];\
						arr1[2] = arr1[10];\
						arr1[6] = arr1[14];\
						arr1[10] = temp[1];\
						arr1[14] = temp[2];\
						arr1[15] = arr1[11];\
						arr1[11] = arr1[7];\
						arr1[7] = arr1[3];\
						arr1[3] = temp[3];

#define invShiftRowsSB(cols1, cols2) cols2[0] = ((uint32_t)InvSBoxes[byte0(cols1[0])]<<24)|(InvSBoxes[byte1(cols1[3])]<<16)|(InvSBoxes[byte2(cols1[2])]<<8)|InvSBoxes[byte3(cols1[1])];\
								   	 cols2[1] = ((uint32_t)InvSBoxes[byte0(cols1[1])]<<24)|(InvSBoxes[byte1(cols1[0])]<<16)|(InvSBoxes[byte2(cols1[3])]<<8)|InvSBoxes[byte3(cols1[2])];\
								   	 cols2[2] = ((uint32_t)InvSBoxes[byte0(cols1[2])]<<24)|(InvSBoxes[byte1(cols1[1])]<<16)|(InvSBoxes[byte2(cols1[0])]<<8)|InvSBoxes[byte3(cols1[3])];\
								   	 cols2[3] = ((uint32_t)InvSBoxes[byte0(cols1[3])]<<24)|(InvSBoxes[byte1(cols1[2])]<<16)|(InvSBoxes[byte2(cols1[1])]<<8)|InvSBoxes[byte3(cols1[0])];


#define firstround(cols, p1, k) cols[0] = (((uint32_t)*p1<<24)|((uint32_t)*(p1+ 1)<<16)|((uint32_t)*(p1+ 2)<<8)|(uint32_t)*(p1+ 3)) ^ Subkeys[k + 0];\
			cols[1] = (((uint32_t)*(p1+ 4)<<24)|((uint32_t)*(p1+ 5)<<16)|((uint32_t)*(p1+ 6)<<8)|(uint32_t)*(p1+ 7)) ^ Subkeys[k + 1];\
			cols[2] = (((uint32_t)*(p1+ 8)<<24)|((uint32_t)*(p1+ 9)<<16)|((uint32_t)*(p1+10)<<8)|(uint32_t)*(p1+ 11)) ^ Subkeys[k + 2];\
			cols[3] = (((uint32_t)*(p1+12)<<24)|((uint32_t)*(p1+13)<<16)|((uint32_t)*(p1+14)<<8)|(uint32_t)*(p1+ 15)) ^ Subkeys[k + 3];\
		

#define lastround(cols, p1, i ) *p1 	= SB(byte0(cols[0])) ^ Subkeys[i]>>24;\
		*(p1+ 1) = SB(byte1(cols[1]))^(uint8_t)(Subkeys[i]>>16);\
		*(p1+ 2) = SB(byte2(cols[2]))^(uint8_t)(Subkeys[i]>>8);\
		*(p1+ 3) = SB(byte3(cols[3]))^(uint8_t)Subkeys[i];\
\
		*(p1+ 4) = SB(byte0(cols[1]))^Subkeys[i+1]>>24;\
		*(p1+ 5) = SB(byte1(cols[2]))^(uint8_t)(Subkeys[i+1]>>16);\
		*(p1+ 6) = SB(byte2(cols[3]))^(uint8_t)(Subkeys[i+1]>>8);\
		*(p1+ 7) = SB(byte3(cols[0]))^(uint8_t)Subkeys[i+1];\
\
		*(p1+ 8) = SB(byte0(cols[2]))^Subkeys[i+2]>>24;\
		*(p1+ 9) = SB(byte1(cols[3]))^(uint8_t)(Subkeys[i+2]>>16);\
		*(p1+10) = SB(byte2(cols[0]))^(uint8_t)(Subkeys[i+2]>>8);\
		*(p1+11) = SB(byte3(cols[1]))^(uint8_t)Subkeys[i+2];\
\
		*(p1+12) = SB(byte0(cols[3]))^Subkeys[i+3]>>24;\
		*(p1+13) = SB(byte1(cols[0]))^(uint8_t)(Subkeys[i+3]>>16);\
		*(p1+14) = SB(byte2(cols[1]))^(uint8_t)(Subkeys[i+3]>>8);\
		*(p1+15) = SB(byte3(cols[2]))^(uint8_t)Subkeys[i+3];

#define lastInvround(cols, p1, i ) *p1 	= (byte0(cols[0])) ^ (Subkeys[i]>>24);\
		*(p1+ 1) = (byte1(cols[0]))^(uint8_t)(Subkeys[i]>>16);\
		*(p1+ 2) = (byte2(cols[0]))^(uint8_t)(Subkeys[i]>>8);\
		*(p1+ 3) = (byte3(cols[0]))^(uint8_t)Subkeys[i];\
\
		*(p1+ 4) = (byte0(cols[1]))^Subkeys[i+1]>>24;\
		*(p1+ 5) = (byte1(cols[1]))^(uint8_t)(Subkeys[i+1]>>16);\
		*(p1+ 6) = (byte2(cols[1]))^(uint8_t)(Subkeys[i+1]>>8);\
		*(p1+ 7) = (byte3(cols[1]))^(uint8_t)Subkeys[i+1];\
\
		*(p1+ 8) = (byte0(cols[2]))^Subkeys[i+2]>>24;\
		*(p1+ 9) = (byte1(cols[2]))^(uint8_t)(Subkeys[i+2]>>16);\
		*(p1+10) = (byte2(cols[2]))^(uint8_t)(Subkeys[i+2]>>8);\
		*(p1+11) = (byte3(cols[2]))^(uint8_t)Subkeys[i+2];\
\
		*(p1+12) = (byte0(cols[3]))^Subkeys[i+3]>>24;\
		*(p1+13) = (byte1(cols[3]))^(uint8_t)(Subkeys[i+3]>>16);\
		*(p1+14) = (byte2(cols[3]))^(uint8_t)(Subkeys[i+3]>>8);\
		*(p1+15) = (byte3(cols[3]))^(uint8_t)Subkeys[i+3];

#define invMixRows(coln1, coln2) coln2[0] = invMixRowCol0[byte0(coln1[0])]^invMixRowCol1[byte1(coln1[0])]^invMixRowCol2[byte2(coln1[0])]^invMixRowCol3[byte3(coln1[0])];\
								 coln2[1] = invMixRowCol0[byte0(coln1[1])]^invMixRowCol1[byte1(coln1[1])]^invMixRowCol2[byte2(coln1[1])]^invMixRowCol3[byte3(coln1[1])];\
								 coln2[2] = invMixRowCol0[byte0(coln1[2])]^invMixRowCol1[byte1(coln1[2])]^invMixRowCol2[byte2(coln1[2])]^invMixRowCol3[byte3(coln1[2])];\
								 coln2[3] = invMixRowCol0[byte0(coln1[3])]^invMixRowCol1[byte1(coln1[3])]^invMixRowCol2[byte2(coln1[3])]^invMixRowCol3[byte3(coln1[3])]; 


#define round(col1, col2, i) col2[0] = MixRowCol0[byte0(col1[0])]^MixRowCol1[byte1(col1[1])]^MixRowCol2[byte2(col1[2])]^MixRowCol3[byte3(col1[3])]^Subkeys[4*i] ;\
							 col2[1] = MixRowCol0[byte0(col1[1])]^MixRowCol1[byte1(col1[2])]^MixRowCol2[byte2(col1[3])]^MixRowCol3[byte3(col1[0])]^Subkeys[4*i+1];\
							 col2[2] = MixRowCol0[byte0(col1[2])]^MixRowCol1[byte1(col1[3])]^MixRowCol2[byte2(col1[0])]^MixRowCol3[byte3(col1[1])]^Subkeys[4*i+2];\
							 col2[3] = MixRowCol0[byte0(col1[3])]^MixRowCol1[byte1(col1[0])]^MixRowCol2[byte2(col1[1])]^MixRowCol3[byte3(col1[2])]^Subkeys[4*i+3];

#define   invround(col1, col2, i) col1[0] ^= Subkeys[4*i];col1[1] ^= Subkeys[4*i+1];\
								  col1[0+2] ^= Subkeys[4*i+2]; col1[3] ^= Subkeys[4*i+3];\
								  invMixRows(col1, col2)\
								  invShiftRowsSB(col2, col1)  



	uint8_t AES::GFMult(int i, uint8_t s) const {
		switch(i){
			case 1:
				return s;
			case 2:
				return GF2[s];
			case 3:
				return GF3[s];
			case 9:
				return GF9[s];
			case 11:
				return GF11[s];
			case 13:
				return GF13[s];
			case 14:
				return GF14[s];
			default:
				return 0;
			}
	}


	void AES::generateKeys(std::string key){
		int target = 64;
		if ((int)key.size() <= 32)
			target = 32;
		else if ((int)key.size() <= 48)
			target = 48;
		int m = target - (int)key.size();
		if (m > 0)
			key.append(m, '0');
		if ((int)key.size() > 64)
			key = key.substr(0,64);
 
		
		int N = key.length()/8;
		int R = 1;
		if (N == 4)
			R = 11;
		if (N == 6)
			R = 13;
		if (N == 8)
			R = 15;

		std::vector<std::vector<uint8_t>> W;
		for(int i=0; i<key.length();i = i+8){
			W.push_back({(uint8_t)std::stoul(key.substr(i,2), 0, 16),
						(uint8_t)std::stoul(key.substr(i+2,2), 0, 16),
						(uint8_t)std::stoul(key.substr(i+4,2), 0, 16),
						(uint8_t)std::stoul(key.substr(i+6,2), 0, 16) });
		}
			
		uint8_t rcon[4] = {1, 0, 0, 0};
		std::vector<uint8_t> T, temp;	
		int t;
		for (int x = N; x<4*R; ++x){
			temp = W[x-1];
			if (x % N == 0){
				if (x-N > 0){
					if (rcon[0] < 128){
						rcon[0] = 2*rcon[0];
					}else{
						rcon[0] = (2*rcon[0])^0x11B;
						if (rcon[0]>255)
							rcon[0] = rcon[0]%256;
					}
				}
				rotl4(temp);
				SubBites4(temp)
				xor4(temp,rcon)
				xor4(temp,W[x - N])
				W.push_back(temp);
			}else if (N > 6 && x % N == 4){
				SubBites4(temp)
				xor4(temp,W[x - N])
				W.push_back(temp);
			}
			else{
				xor4(temp,W[x - N])
				W.push_back(temp);
			}
		}
		Subkeys.clear();
		for (int i=0;i<4*R;++i)
			Subkeys.push_back(((uint32_t)W[i][0]<<24)|((uint32_t)W[i][1]<<16)|((uint32_t)W[i][2]<<8)|W[i][3] );
		
		
		
	}

	void AES::encrypt_block128(uint8_t *p) const
	{	
		uint8_t temp[16];

		uint32_t columnA[4];
		uint32_t columnB[4];
		
		firstround(columnA, p,0)
		round(columnA,columnB,1)
		round(columnB,columnA,2)
		round(columnA,columnB,3)
		round(columnB,columnA,4)
		round(columnA,columnB,5)
		round(columnB,columnA,6)
		round(columnA,columnB,7)
		round(columnB,columnA,8)
		round(columnA,columnB,9)

		lastround(columnB, p, 40)

	}

	void AES::encrypt_block192(uint8_t *p) const
	{	
		uint8_t temp[16];

		uint32_t columnA[4];
		uint32_t columnB[4];

		firstround(columnA, p, 0)
		round(columnA,columnB, 1)
		round(columnB,columnA, 2)
		round(columnA,columnB, 3)
		round(columnB,columnA, 4)
		round(columnA,columnB, 5)
		round(columnB,columnA, 6)
		round(columnA,columnB, 7)
		round(columnB,columnA, 8)
		round(columnA,columnB, 9)
		round(columnB,columnA,10)
		round(columnA,columnB,11)

		lastround(columnB, p, 48)
	}

	void AES::encrypt_block256(uint8_t *p) const
	{	
		uint8_t temp[16];


		uint32_t columnA[4];
		uint32_t columnB[4];

		firstround(columnA, p, 0)
		round(columnA,columnB, 1)
		round(columnB,columnA, 2)
		round(columnA,columnB, 3)
		round(columnB,columnA, 4)
		round(columnA,columnB, 5)
		round(columnB,columnA, 6)
		round(columnA,columnB, 7)
		round(columnB,columnA, 8)
		round(columnA,columnB, 9)
		round(columnB,columnA,10)
		round(columnA,columnB,11)
		round(columnB,columnA,12)
		round(columnA,columnB,13)

		lastround(columnB, p, 56)
	}

	void AES::decrypt_block128(uint8_t *p) const
	{	
		uint8_t temp[16];
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		firstround(columnB, p, 40)
		invShiftRowsSB(columnB, columnA)

		invround(columnA,columnB, 9)
		invround(columnA,columnB, 8)
		invround(columnA,columnB, 7)
		invround(columnA,columnB, 6)
		invround(columnA,columnB, 5)
		invround(columnA,columnB, 4)
		invround(columnA,columnB, 3)
		invround(columnA,columnB, 2)
		invround(columnA,columnB, 1)

		lastInvround(columnA, p, 0)		
	}


	void AES::decrypt_block192(uint8_t *p) const
	{	
		uint8_t temp[16];
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		firstround(columnB, p, 48)
		invShiftRowsSB(columnB, columnA)

		invround(columnA,columnB,11)
		invround(columnA,columnB,10)
		invround(columnA,columnB, 9)
		invround(columnA,columnB, 8)
		invround(columnA,columnB, 7)
		invround(columnA,columnB, 6)
		invround(columnA,columnB, 5)
		invround(columnA,columnB, 4)
		invround(columnA,columnB, 3)
		invround(columnA,columnB, 2)
		invround(columnA,columnB, 1)

		lastInvround(columnA, p, 0)		
	}

void AES::decrypt_block256(uint8_t *p) const
	{	
		uint8_t temp[16];
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		firstround(columnB, p, 56)
		invShiftRowsSB(columnB, columnA)

		invround(columnA,columnB,13)
		invround(columnA,columnB,12)
		invround(columnA,columnB,11)
		invround(columnA,columnB,10)
		invround(columnA,columnB, 9)
		invround(columnA,columnB, 8)
		invround(columnA,columnB, 7)
		invround(columnA,columnB, 6)
		invround(columnA,columnB, 5)
		invround(columnA,columnB, 4)
		invround(columnA,columnB, 3)
		invround(columnA,columnB, 2)
		invround(columnA,columnB, 1)

		lastInvround(columnA, p, 0)		

	}



	int AES::blockSize() const
	{
		return 16;
	}

	void AES::encryptBlock(uint8_t *block) const
	{
		switch(Subkeys.size())
		{
			case 60: encrypt_block256(block); break;
			case 52: encrypt_block192(block); break;
			case 44: encrypt_block128(block); break;
		}
	}

	void AES::decryptBlock(uint8_t *block) const
	{
		switch(Subkeys.size())
		{
			case 60: decrypt_block256(block); break;
			case 52: decrypt_block192(block); break;
			case 44: decrypt_block128(block); break;
		}
	}

	void AES::encrypt(uint8_t *plt, int len) const
	{
		encryptECB(plt, len);
	}

	std::vector<uint8_t> AES::encrypt(std::vector<uint8_t> plt) const
	{
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

	void AES::decrypt(uint8_t *plt, int len) const
	{
		decryptECB(plt, len);
	}

	std::vector<uint8_t> AES::decrypt(std::vector<uint8_t> plt) const
	{
		return decryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}




