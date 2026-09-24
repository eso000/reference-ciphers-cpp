#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "DES.h"


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

static const uint32_t SPBox[8][64] = {
	{0x00808200, 0x00000000, 0x00008000, 0x00808202, 0x00808002, 0x00008202, 0x00000002, 0x00008000, 0x00000200, 0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002, 0x00800000, 0x00000002, 0x00000202, 0x00800200, 0x00800200, 0x00008200, 0x00008200, 0x00808000, 0x00808000, 0x00800202, 0x00008002, 0x00800002, 0x00800002, 0x00008002, 0x00000000, 0x00000202, 0x00008202, 0x00800000, 0x00008000, 0x00808202, 0x00000002, 0x00808000, 0x00808200, 0x00800000, 0x00800000, 0x00000200, 0x00808002, 0x00008000, 0x00008200, 0x00800002, 0x00000200, 0x00000002, 0x00800202, 0x00008202, 0x00808202, 0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202, 0x00008202, 0x00808200, 0x00000202, 0x00800200, 0x00800200, 0x00000000, 0x00008002, 0x00008200, 0x00000000, 0x00808002},
	{0x40084010, 0x40004000, 0x00004000, 0x00084010, 0x00080000, 0x00000010, 0x40080010, 0x40004010, 0x40000010, 0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000, 0x00000010, 0x40080010, 0x00084000, 0x00080010, 0x40004010, 0x00000000, 0x40000000, 0x00004000, 0x00084010, 0x40080000, 0x00080010, 0x40000010, 0x00000000, 0x00084000, 0x00004010, 0x40084000, 0x40080000, 0x00004010, 0x00000000, 0x00084010, 0x40080010, 0x00080000, 0x40004010, 0x40080000, 0x40084000, 0x00004000, 0x40080000, 0x40004000, 0x00000010, 0x40084010, 0x00084010, 0x00000010, 0x00004000, 0x40000000, 0x00004010, 0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010, 0x40000010, 0x00080010, 0x00084000, 0x00000000, 0x40004000, 0x00004010, 0x40000000, 0x40080010, 0x40084010, 0x00084000},
	{0x00000104, 0x04010100, 0x00000000, 0x04010004, 0x04000100, 0x00000000, 0x00010104, 0x04000100, 0x00010004, 0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004, 0x04010000, 0x00000104, 0x04000000, 0x00000004, 0x04010100, 0x00000100, 0x00010100, 0x04010000, 0x04010004, 0x00010104, 0x04000104, 0x00010100, 0x00010000, 0x04000104, 0x00000004, 0x04010104, 0x00000100, 0x04000000, 0x04010100, 0x04000000, 0x00010004, 0x00000104, 0x00010000, 0x04010100, 0x04000100, 0x00000000, 0x00000100, 0x00010004, 0x04010104, 0x04000100, 0x04000004, 0x00000100, 0x00000000, 0x04010004, 0x04000104, 0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104, 0x00010100, 0x04000004, 0x04010000, 0x04000104, 0x00000104, 0x04010000, 0x00010104, 0x00000004, 0x04010004, 0x00010100},
	{0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x00401040, 0x80400040, 0x80400000, 0x80001000, 0x00000000, 0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00400040, 0x80400000, 0x80000000, 0x00001000, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x80001000, 0x00001040, 0x80400040, 0x80000000, 0x00001040, 0x00400040, 0x00001000, 0x00401040, 0x80401040, 0x80000040, 0x00400040, 0x80400000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00000000, 0x00401000, 0x00001040, 0x00400040, 0x80400040, 0x80000000, 0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x80401040, 0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000, 0x00401040, 0x80400040, 0x80001000, 0x00001040, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x00001000, 0x00401040},
	{0x00000080, 0x01040080, 0x01040000, 0x21000080, 0x00040000, 0x00000080, 0x20000000, 0x01040000, 0x20040080, 0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000, 0x00040080, 0x20000000, 0x01000000, 0x20040000, 0x20040000, 0x00000000, 0x20000080, 0x21040080, 0x21040080, 0x01000080, 0x21040000, 0x20000080, 0x00000000, 0x21000000, 0x01040080, 0x01000000, 0x21000000, 0x00040080, 0x00040000, 0x21000080, 0x00000080, 0x01000000, 0x20000000, 0x01040000, 0x21000080, 0x20040080, 0x01000080, 0x20000000, 0x21040000, 0x01040080, 0x20040080, 0x00000080, 0x01000000, 0x21040000, 0x21040080, 0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000, 0x20040000, 0x21000000, 0x00040080, 0x01000080, 0x20000080, 0x00040000, 0x00000000, 0x20040000, 0x01040080, 0x20000080},
	{0x10000008, 0x10200000, 0x00002000, 0x10202008, 0x10200000, 0x00000008, 0x10202008, 0x00200000, 0x10002000, 0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000, 0x10000000, 0x00002008, 0x00000000, 0x00200008, 0x10002008, 0x00002000, 0x00202000, 0x10002008, 0x00000008, 0x10200008, 0x10200008, 0x00000000, 0x00202008, 0x10202000, 0x00002008, 0x00202000, 0x10202000, 0x10000000, 0x10002000, 0x00000008, 0x10200008, 0x00202000, 0x10202008, 0x00200000, 0x00002008, 0x10000008, 0x00200000, 0x10002000, 0x10000000, 0x00002008, 0x10000008, 0x10202008, 0x00202000, 0x10200000, 0x00202008, 0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000, 0x10200000, 0x00202008, 0x00002000, 0x00200008, 0x10002008, 0x00000000, 0x10202000, 0x10000000, 0x00200008, 0x10002008},
	{0x00100000, 0x02100001, 0x02000401, 0x00000000, 0x00000400, 0x02000401, 0x00100401, 0x02100400, 0x02100401, 0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000, 0x02100001, 0x00000401, 0x02000400, 0x00100401, 0x00100001, 0x02000400, 0x02000001, 0x02100000, 0x02100400, 0x00100001, 0x02100000, 0x00000400, 0x00000401, 0x02100401, 0x00100400, 0x00000001, 0x02000000, 0x00100400, 0x02000000, 0x00100400, 0x00100000, 0x02000401, 0x02000401, 0x02100001, 0x02100001, 0x00000001, 0x00100001, 0x02000000, 0x02000400, 0x00100000, 0x02100400, 0x00000401, 0x00100401, 0x02100400, 0x00000401, 0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000, 0x00000001, 0x02100401, 0x00000000, 0x00100401, 0x02100000, 0x00000400, 0x02000001, 0x02000400, 0x00000400, 0x00100001},
	{0x08000820, 0x00000800, 0x00020000, 0x08020820, 0x08000000, 0x08000820, 0x00000020, 0x08000000, 0x00020020, 0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820, 0x00000800, 0x00000020, 0x08020000, 0x08000020, 0x08000800, 0x00000820, 0x00020800, 0x00020020, 0x08020020, 0x08020800, 0x00000820, 0x00000000, 0x00000000, 0x08020020, 0x08000020, 0x08000800, 0x00020820, 0x00020000, 0x00020820, 0x00020000, 0x08020800, 0x00000800, 0x00000020, 0x08020020, 0x00000800, 0x00020820, 0x08000800, 0x00000020, 0x08000020, 0x08020000, 0x08020020, 0x08000000, 0x00020000, 0x08000820, 0x00000000, 0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800, 0x08000820, 0x00000000, 0x08020820, 0x00020800, 0x00020800, 0x00000820, 0x00000820, 0x00020020, 0x08000000, 0x08020800},
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

