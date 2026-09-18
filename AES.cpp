
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



#define padPKCS(pvec, missing) for (int i = 0; i < missing; ++i)\
                                                                pvec.push_back((uint8_t) missing);

#define padZeros(pvec, missing) for (int i = 0; i < missing; ++i)\
                                                                pvec.push_back((uint8_t) 0);

#define padANSIX923(pvec, missing) for (int i = 0; i < missing-1; ++i)\
                                                                        pvec.push_back((uint8_t) 0);\
                                                                   pvec.push_back((uint8_t) missing);

#define padISO78164(pvec, missing) pvec.push_back((uint8_t) 0x80);\
                                                                   for (int i = 0; i < missing-1; ++i)\
                                                                                pvec.push_back((uint8_t) 0);\



#define pad(pvec, missing) for(int i = 0; i < missing; ++i)\
                                        pvec.push_back('0');






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

#define invShiftRowsSB(cols1, cols2) cols2[0] = (InvSBoxes[byte0(cols1[0])]<<24)|(InvSBoxes[byte1(cols1[3])]<<16)|(InvSBoxes[byte2(cols1[2])]<<8)|InvSBoxes[byte3(cols1[1])];\
								   	 cols2[1] = (InvSBoxes[byte0(cols1[1])]<<24)|(InvSBoxes[byte1(cols1[0])]<<16)|(InvSBoxes[byte2(cols1[3])]<<8)|InvSBoxes[byte3(cols1[2])];\
								   	 cols2[2] = (InvSBoxes[byte0(cols1[2])]<<24)|(InvSBoxes[byte1(cols1[1])]<<16)|(InvSBoxes[byte2(cols1[0])]<<8)|InvSBoxes[byte3(cols1[3])];\
								   	 cols2[3] = (InvSBoxes[byte0(cols1[3])]<<24)|(InvSBoxes[byte1(cols1[2])]<<16)|(InvSBoxes[byte2(cols1[1])]<<8)|InvSBoxes[byte3(cols1[0])];


#define firstround(cols, p1, k) cols[0] = ((*p1<<24)|(*(p1+ 1)<<16)|(*(p1+ 2)<<8)|*(p1+ 3)) ^ Subkeys[k + 0];\
			cols[1] = ((*(p1+ 4)<<24)|(*(p1+ 5)<<16)|(*(p1+ 6)<<8)|*(p1+ 7)) ^ Subkeys[k + 1];\
			cols[2] = ((*(p1+ 8)<<24)|(*(p1+ 9)<<16)|(*(p1+10)<<8)|*(p1+ 11)) ^ Subkeys[k + 2];\
			cols[3] = ((*(p1+12)<<24)|(*(p1+13)<<16)|(*(p1+14)<<8)|*(p1+ 15)) ^ Subkeys[k + 3];\
		

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



	uint8_t AES::GFMult(int i, uint8_t s){
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
			pad(key, m);
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
			Subkeys.push_back((W[i][0]<<24)|(W[i][1]<<16)|(W[i][2]<<8)|W[i][3] );
		
		
		
	}

	void AES::encrypt_block128(uint8_t *p)
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

	void AES::encrypt_block192(uint8_t *p)
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

	void AES::encrypt_block256(uint8_t *p)
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

	void AES::decrypt_block128(uint8_t *p)
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


	void AES::decrypt_block192(uint8_t *p)
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

void AES::decrypt_block256(uint8_t *p)
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



	void AES::encrypt(uint8_t *plt, int len)
	{	
		switch(Subkeys.size())
		{
			case 60:
				for(uint8_t *i = plt; i+16<=plt + len; i = i + 16)
					encrypt_block256(i);
				break;
			case 52:
				for(uint8_t *i = plt; i+16<=plt + len; i = i + 16)
					encrypt_block192(i);
				break;
			case 44:
				for(uint8_t *i = plt; i+16<=plt + len; i = i + 16)
					encrypt_block128(i);
				break;

		}
		
	}
	std::vector<uint8_t> AES::encrypt(std::vector<uint8_t> plt)
	{
		int l = plt.size();
		int m = 16 - (l%16);
		for (int i = 0; i < m; ++i)
			plt.push_back((uint8_t) m);
		encrypt(&plt[0], plt.size());
		return plt;
	}

	void AES::decrypt(uint8_t *plt, int len)
	{
		switch(Subkeys.size())
		{
			case 60:
				for(uint8_t *i = plt; i+16<=plt + len; i = i + 16)
					decrypt_block256(i);
				break;
			case 52:
				for(uint8_t *i = plt; i+16<=plt + len; i = i + 16)
					decrypt_block192(i);
				break;
			case 44:
				for(uint8_t *i = plt; i+16<=plt + len; i = i + 16)
					decrypt_block128(i);
				break;
		}
	}


	std::vector<uint8_t> AES::decrypt(std::vector<uint8_t> plt)
	{
		decrypt(&plt[0], plt.size());
		int l = plt.size();
		if (l > 0)
		{
			int padok = 1;
			uint8_t n = plt[l-1];
			if (n < 1 || n > 16)
				padok = 0;
			for (int i = 0; i < n && padok; ++i)
				if (plt[l-1-i] != n)
					padok = 0;
			if (padok)
				plt.resize(l - n);
		}
		return plt;
	}




