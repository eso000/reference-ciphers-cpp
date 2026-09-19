#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "DES.h"

#define padPKCS(pvec, missing) for (int i = 0; i < missing; ++i)\
								pvec.push_back((uint8_t) missing);\

#define copy8(arr1, arr2) arr1[0] = *arr2;\
	arr1[1] = *(arr2+1);\
	arr1[2] = *(arr2+2);\
	arr1[3] = *(arr2+3);\
	arr1[4] = *(arr2+4);\
	arr1[5] = *(arr2+5);\
	arr1[6] = *(arr2+6);\
	arr1[7] = *(arr2+7);

#define xor8(arr1, arr2) arr1[0] ^= *arr2;\
	arr1[1] ^= *(arr2+1);\
	arr1[2] ^= *(arr2+2);\
	arr1[3] ^= *(arr2+3);\
	arr1[4] ^= *(arr2+4);\
	arr1[5] ^= *(arr2+5);\
	arr1[6] ^= *(arr2+6);\
	arr1[7] ^= *(arr2+7);

#define rotr28(xr,times) (((xr << times)|(xr >> 28-times)))&0xFFFFFFF

#define F(x,i) temp = permutate(x.w, ExpentionPerm,32)^Subkeys[i];\
			   temp = SBoxes0[temp>>42] << 28 | SBoxes1[temp>>36&0b111111] << 24 | SBoxes2[temp>>30&0b111111] << 20\
			   | SBoxes3[temp>>24&0b111111] << 16 | SBoxes4[temp>>18&0b111111] << 12 | SBoxes5[temp>>12&0b111111] << 8\
			   | SBoxes6[temp>>6&0b111111] << 4| SBoxes7[temp&0b111111];\
			   temp = permutate(temp, PBox,32);

#define round(l,r,i) F(r,i); l.w ^= temp;

union word{
	uint32_t w;
	uint8_t b[4];
};


	uint64_t DES::permutate(uint64_t x, std::vector<uint8_t> P, int base_size) const
	{
		uint64_t result = 0;
		for (int i = 0; i < P.size(); ++i)
		{
			result <<= 1;
			result |= (x>>(base_size-P[i])&1);
		}
		return result;
	}

	void DES::generateKeys(std::string key){
		if (key.size() != 16)
			throw std::invalid_argument("DES key must be 16 hex characters");
		Subkeys.clear();
		uint64_t leftKey = std::stoull(key, 0, 16);
		leftKey = permutate(leftKey, keyperm1, 64);
		uint64_t rightKey = leftKey&0b1111111111111111111111111111;
		leftKey >>= 28;
		int shift;
		for (int i =0;i<16;i++){
			shift = 2;
			if ((i + 1 ==  1) || (i + 1 ==  2)|| (i + 1 ==  9)||(i + 1 ==  16)){
				shift = 1;
			}
			leftKey = rotr28(leftKey, shift);
			rightKey = rotr28(rightKey, shift);
			Subkeys.push_back(permutate( (leftKey<<28)| rightKey,keyperm2, 28*2));
		}
	}

	void DES::encrypt_block(uint8_t *lb,uint8_t *rb) const
	{
		union word left, right;
		left.b[3] = *lb; left.b[2] = *(lb+1); left.b[1] = *(lb+2); left.b[0] = *(lb+3);
		right.b[3] = *rb; right.b[2] = *(rb+1); right.b[1] = *(rb+2); right.b[0] = *(rb+3);

		uint64_t temp;
		temp = permutate((uint64_t)left.w<<32|right.w,initialperm, 64);
		left.w = temp >>32;
		right.w = temp &0xffffffffl;

		round (left, right, 0) ;  round (right, left, 1) ;
		round (left, right, 2) ;  round (right, left, 3) ;
		round (left, right, 4) ;  round (right, left, 5) ;
		round (left, right, 6) ;  round (right, left, 7) ;
		round (left, right, 8) ;  round (right, left, 9) ;
		round (left, right, 10) ; round (right, left, 11) ;
		round (left, right, 12) ; round (right, left, 13) ;
		round (left, right, 14) ; round (right, left, 15) ;

		temp = permutate((uint64_t)right.w<<32|left.w,inverseperm, 64);

		right.w = temp &0xffffffffl;
		left.w = temp >> 32;
		*lb = left.b[3]; *(lb+1) = left.b[2]; *(lb+2) = left.b[1]; *(lb+3) = left.b[0];
		*rb = right.b[3]; *(rb+1) = right.b[2]; *(rb+2) = right.b[1];*(rb+3) = right.b[0];
	}

	void DES::decrypt_block(uint8_t *lb,uint8_t *rb) const
	{
		union word left, right;
		left.b[3] = *lb; left.b[2] = *(lb+1); left.b[1] = *(lb+2); left.b[0] = *(lb+3);
		right.b[3] = *rb; right.b[2] = *(rb+1); right.b[1] = *(rb+2); right.b[0] = *(rb+3);

		uint64_t temp;
		temp = permutate((uint64_t)left.w<<32|right.w,initialperm, 64);
		left.w = temp >>32;
		right.w = temp &0xffffffffl;

		round (left, right, 15) ;  round (right, left, 14) ;
		round (left, right, 13) ;  round (right, left, 12) ;
		round (left, right, 11) ;  round (right, left, 10) ;
		round (left, right,  9) ;  round (right, left,  8) ;
		round (left, right,  7) ;  round (right, left,  6) ;
		round (left, right,  5) ;  round (right, left,  4) ;
		round (left, right,  3) ;  round (right, left,  2) ;
		round (left, right,  1) ;  round (right, left,  0) ;

		temp = permutate((uint64_t)right.w<<32|left.w,inverseperm, 64);

		right.w = temp &0xffffffffl;
		left.w = temp >> 32;
		*lb = left.b[3]; *(lb+1) = left.b[2]; *(lb+2) = left.b[1]; *(lb+3) = left.b[0];
		*rb = right.b[3]; *(rb+1) = right.b[2]; *(rb+2) = right.b[1];*(rb+3) = right.b[0];
	}

	void DES::encryptECB(uint8_t *plt, int len) const
	{
		for(uint8_t *i = plt; i+8<=plt + len; i = i + 8)
			encrypt_block(i,i+4);
	}

	void DES::decryptECB(uint8_t *plt, int len) const
	{
		for(uint8_t *i = plt; i+8<=plt + len; i = i + 8)
			decrypt_block(i,i+4);
	}

	void DES::encryptCBC(uint8_t *plt, int len, uint8_t *iv) const
	{
		for(uint8_t *i = plt; i+8<=plt + len; i = i + 8)
		{
			xor8(i,iv)
			encrypt_block(i,i+4);
			iv = i;
		}
	}

	void DES::decryptCBC(uint8_t *plt, int len, uint8_t *iv) const
	{
		uint8_t t[8];
		for(uint8_t *i = plt; i+8<=plt + len; i = i + 8)
		{
			copy8(t,i)
			decrypt_block(i,i+4);
			xor8(i,iv)
			copy8(iv,t)
		}
	}

	std::vector<uint8_t> DES::encrypt(std::vector<uint8_t> plt) const
	{
		int l = plt.size();
		int m = 8 - (l%8);
		padPKCS(plt, m)

		encryptECB(&plt[0], plt.size());

		return plt;
	}

	std::vector<uint8_t> DES::decrypt(std::vector<uint8_t> plt) const
	{
		if (plt.empty())
			return plt;
		decryptECB(&plt[0], plt.size());
		int l = plt.size();
		int padok = 1;
		uint8_t n = plt[l-1];
		if (n < 1 || n > 8)
			padok = 0;
		for (int i = 0; i < n && padok; ++i)
			if (plt[l-1-i] != n)
				padok = 0;
		if (padok)
			plt.resize(l - n);
		return plt;
	}

	void DES::encrypt_File(char* path) const
	{
		std::ifstream input_file(path, std::ios::binary);
		std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
		input_file.close();
		int m = 8 - (vec.size()%8);
		padPKCS(vec, m)
		encryptECB(&vec[0], vec.size());
		std::ofstream file(path);
		file.write(reinterpret_cast<char*>(&vec[0]), vec.size());
    	file.close();
	}

	void DES::decrypt_File(char* path) const
	{
		std::ifstream input_file(path, std::ios::binary);
		std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
		input_file.close();
		decryptECB(&vec[0], vec.size());
		int l = vec.size();
		if (l > 0)
		{
			int padok = 1;
			uint8_t n = vec[l-1];
			if (n < 1 || n > 8)
				padok = 0;
			for (int i = 0; i < n && padok; ++i)
				if (vec[l-1-i] != n)
					padok = 0;
			if (padok)
				vec.resize(l - n);
		}
		std::ofstream file(path);
		if (!vec.empty())
			file.write(reinterpret_cast<char*>(&vec[0]), vec.size());
    	file.close();
	}
