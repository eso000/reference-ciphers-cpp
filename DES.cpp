#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "DES.h"
#include <iterator>
#include "DES_data.h"

DES::DES(bool useAlt) : use_alt(useAlt)
{
	initialperm.assign(std::begin(initialperm_data), std::end(initialperm_data));
	inverseperm.assign(std::begin(inverseperm_data), std::end(inverseperm_data));
	ExpentionPerm.assign(std::begin(ExpentionPerm_data), std::end(ExpentionPerm_data));
	SBoxes0.assign(std::begin(SBoxes0_data), std::end(SBoxes0_data));
	SBoxes1.assign(std::begin(SBoxes1_data), std::end(SBoxes1_data));
	SBoxes2.assign(std::begin(SBoxes2_data), std::end(SBoxes2_data));
	SBoxes3.assign(std::begin(SBoxes3_data), std::end(SBoxes3_data));
	SBoxes4.assign(std::begin(SBoxes4_data), std::end(SBoxes4_data));
	SBoxes5.assign(std::begin(SBoxes5_data), std::end(SBoxes5_data));
	SBoxes6.assign(std::begin(SBoxes6_data), std::end(SBoxes6_data));
	SBoxes7.assign(std::begin(SBoxes7_data), std::end(SBoxes7_data));
	keyperm1.assign(std::begin(keyperm1_data), std::end(keyperm1_data));
	keyperm2.assign(std::begin(keyperm2_data), std::end(keyperm2_data));
	PBox.assign(std::begin(PBox_data), std::end(PBox_data));
}



#define rotr28(xr,times) (((xr << times)|(xr >> 28-times)))&0xFFFFFFF

	#define F(x,i) temp = permutate(x.w, ExpentionPerm,32)^Subkeys[i];\
				   if (use_alt)\
				   temp = SPBox[0][(temp>>42)&0x3f] ^ SPBox[1][(temp>>36)&0x3f] ^ SPBox[2][(temp>>30)&0x3f] ^ SPBox[3][(temp>>24)&0x3f]\
				   ^ SPBox[4][(temp>>18)&0x3f] ^ SPBox[5][(temp>>12)&0x3f] ^ SPBox[6][(temp>>6)&0x3f] ^ SPBox[7][temp&0x3f];\
				   else {\
				   temp = SBoxes0[temp>>42] << 28 | SBoxes1[temp>>36&0b111111] << 24 | SBoxes2[temp>>30&0b111111] << 20\
				   | SBoxes3[temp>>24&0b111111] << 16 | SBoxes4[temp>>18&0b111111] << 12 | SBoxes5[temp>>12&0b111111] << 8\
				   | SBoxes6[temp>>6&0b111111] << 4| SBoxes7[temp&0b111111];\
				   temp = permutate(temp, PBox,32);\
				   }
#define round(l,r,i) F(r,i); l.w ^= temp;

union word{
	uint32_t w;
	uint8_t b[4];
};

static inline uint32_t rol32(uint32_t x, int n)
{
	n &= 31;
	if (!n)
		return x;
	return (x << n) | (x >> (32 - n));
}

static inline uint32_t ror32(uint32_t x, int n)
{
	n &= 31;
	if (!n)
		return x;
	return (x >> n) | (x << (32 - n));
}

uint64_t DES::ip_perm_alt(uint64_t block)
{
	uint32_t left = block >> 32;
	uint32_t right = block & 0xffffffff;
	uint32_t work;

	right = rol32(right, 4);
	work = (left ^ right) & 0xf0f0f0f0;
	left ^= work;
	right = ror32(right ^ work, 20);
	work = (left ^ right) & 0xffff0000;
	left ^= work;
	right = ror32(right ^ work, 18);
	work = (left ^ right) & 0x33333333;
	left ^= work;
	right = ror32(right ^ work, 6);
	work = (left ^ right) & 0x00ff00ff;
	left ^= work;
	right = rol32(right ^ work, 9);
	work = (left ^ right) & 0xaaaaaaaa;
	left = rol32(left ^ work, 1);
	right ^= work;
	return ((uint64_t)rol32(left, 31) << 32) | rol32(right, 31);
}

uint64_t DES::fp_perm_alt(uint64_t block)
{
	uint32_t left = block >> 32;
	uint32_t right = block & 0xffffffff;
	uint32_t work;

	left = rol32(left, 1);
	right = rol32(right, 1);
	work = (ror32(left, 1) ^ right) & 0xaaaaaaaa;
	left = ror32(left, 1) ^ work;
	right ^= work;
	work = (left ^ ror32(right, 9)) & 0x00ff00ff;
	left ^= work;
	right = ror32(right, 9) ^ work;
	work = (left ^ rol32(right, 6)) & 0x33333333;
	left ^= work;
	right = rol32(right, 6) ^ work;
	work = (left ^ rol32(right, 18)) & 0xffff0000;
	left ^= work;
	right = rol32(right, 18) ^ work;
	work = (left ^ rol32(right, 20)) & 0xf0f0f0f0;
	left ^= work;
	right = rol32(right, 20) ^ work;
	right = ror32(right, 4);
	return ((uint64_t)left << 32) | right;
}



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
			throw std::invalid_argument("DES key must be 16 hex characters, got " + std::to_string(key.size()));
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
		if (use_alt)
			temp = ip_perm_alt((uint64_t)left.w << 32 | right.w);
		else
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

		if (use_alt)
			temp = fp_perm_alt((uint64_t)right.w << 32 | left.w);
		else
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
		if (use_alt)
			temp = ip_perm_alt((uint64_t)left.w << 32 | right.w);
		else
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

		if (use_alt)
			temp = fp_perm_alt((uint64_t)right.w << 32 | left.w);
		else
					temp = permutate((uint64_t)right.w<<32|left.w,inverseperm, 64);

		right.w = temp &0xffffffffl;
		left.w = temp >> 32;
		*lb = left.b[3]; *(lb+1) = left.b[2]; *(lb+2) = left.b[1]; *(lb+3) = left.b[0];
		*rb = right.b[3]; *(rb+1) = right.b[2]; *(rb+2) = right.b[1];*(rb+3) = right.b[0];
	}

	int DES::blockSize() const
	{
		return 8;
	}

	void DES::encryptBlock(uint8_t *block) const
	{
		encrypt_block(block, block + 4);
	}

	void DES::decryptBlock(uint8_t *block) const
	{
		decrypt_block(block, block + 4);
	}

	std::vector<uint8_t> DES::encrypt(std::vector<uint8_t> plt) const
	{
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

	std::vector<uint8_t> DES::decrypt(std::vector<uint8_t> plt) const
	{
		return decryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}
