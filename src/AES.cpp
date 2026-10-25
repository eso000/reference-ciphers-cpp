
#include <vector>
#include <string>
#include <stdexcept>



#include "block/AES.h"
#include <iterator>
#include "AES_data.h"
#include "bits.h"
#include "force_inline.h"

namespace block {

using namespace detail;

AES::AES()
{
	SBoxes.assign(std::begin(SBoxes_data), std::end(SBoxes_data));
	InvSBoxes.assign(std::begin(InvSBoxes_data), std::end(InvSBoxes_data));
	GF2.assign(std::begin(GF2_data), std::end(GF2_data));
	GF3.assign(std::begin(GF3_data), std::end(GF3_data));
	GF9.assign(std::begin(GF9_data), std::end(GF9_data));
	GF11.assign(std::begin(GF11_data), std::end(GF11_data));
	GF13.assign(std::begin(GF13_data), std::end(GF13_data));
	GF14.assign(std::begin(GF14_data), std::end(GF14_data));
	MixRowCol0.assign(std::begin(MixRowCol0_data), std::end(MixRowCol0_data));
	MixRowCol1.assign(std::begin(MixRowCol1_data), std::end(MixRowCol1_data));
	MixRowCol2.assign(std::begin(MixRowCol2_data), std::end(MixRowCol2_data));
	MixRowCol3.assign(std::begin(MixRowCol3_data), std::end(MixRowCol3_data));
	invMixRowCol0.assign(std::begin(invMixRowCol0_data), std::end(invMixRowCol0_data));
	invMixRowCol1.assign(std::begin(invMixRowCol1_data), std::end(invMixRowCol1_data));
	invMixRowCol2.assign(std::begin(invMixRowCol2_data), std::end(invMixRowCol2_data));
	invMixRowCol3.assign(std::begin(invMixRowCol3_data), std::end(invMixRowCol3_data));
}




/* The key schedule works on four-byte columns: rotate, SubBytes and XOR. */
FORCE_INLINE void aes_rotl4(uint8_t *a)
{
	uint8_t t = a[0];
	a[0] = a[1];
	a[1] = a[2];
	a[2] = a[3];
	a[3] = t;
}

FORCE_INLINE void aes_xor4(uint8_t *a, const uint8_t *b)
{
	a[0] ^= b[0];
	a[1] ^= b[1];
	a[2] ^= b[2];
	a[3] ^= b[3];
}

FORCE_INLINE void aes_xor4(std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
	aes_xor4(a.data(), b.data());
}

FORCE_INLINE void aes_subBytes4(uint8_t *a, const std::vector<uint8_t> &sbox)
{
	a[0] = sbox[a[0]];
	a[1] = sbox[a[1]];
	a[2] = sbox[a[2]];
	a[3] = sbox[a[3]];
}

/* Loads the block into columns and applies the first round key. */
FORCE_INLINE void aes_firstRound(uint32_t cols[4], const uint8_t *p, const AES &a, int k)
{
	cols[0] = (((uint32_t)p[ 0]<<24)|((uint32_t)p[ 1]<<16)|((uint32_t)p[ 2]<<8)|(uint32_t)p[ 3]) ^ a.Subkeys[k + 0];
	cols[1] = (((uint32_t)p[ 4]<<24)|((uint32_t)p[ 5]<<16)|((uint32_t)p[ 6]<<8)|(uint32_t)p[ 7]) ^ a.Subkeys[k + 1];
	cols[2] = (((uint32_t)p[ 8]<<24)|((uint32_t)p[ 9]<<16)|((uint32_t)p[10]<<8)|(uint32_t)p[11]) ^ a.Subkeys[k + 2];
	cols[3] = (((uint32_t)p[12]<<24)|((uint32_t)p[13]<<16)|((uint32_t)p[14]<<8)|(uint32_t)p[15]) ^ a.Subkeys[k + 3];
}

/* SubBytes, ShiftRows, MixColumns and AddRoundKey through the T-tables. */
FORCE_INLINE void aes_round(const uint32_t col1[4], uint32_t col2[4], const AES &a, int i)
{
	col2[0] = a.MixRowCol0[byte0(col1[0])]^a.MixRowCol1[byte1(col1[1])]^a.MixRowCol2[byte2(col1[2])]^a.MixRowCol3[byte3(col1[3])]^a.Subkeys[4*i];
	col2[1] = a.MixRowCol0[byte0(col1[1])]^a.MixRowCol1[byte1(col1[2])]^a.MixRowCol2[byte2(col1[3])]^a.MixRowCol3[byte3(col1[0])]^a.Subkeys[4*i+1];
	col2[2] = a.MixRowCol0[byte0(col1[2])]^a.MixRowCol1[byte1(col1[3])]^a.MixRowCol2[byte2(col1[0])]^a.MixRowCol3[byte3(col1[1])]^a.Subkeys[4*i+2];
	col2[3] = a.MixRowCol0[byte0(col1[3])]^a.MixRowCol1[byte1(col1[0])]^a.MixRowCol2[byte2(col1[1])]^a.MixRowCol3[byte3(col1[2])]^a.Subkeys[4*i+3];
}

/* The last encryption step: SubBytes, ShiftRows, AddRoundKey and store. */
FORCE_INLINE void aes_lastRound(const uint32_t cols[4], uint8_t *p, const AES &a, int i)
{
	p[ 0] = a.SBoxes[byte0(cols[0])] ^ (uint8_t)(a.Subkeys[i]>>24);
	p[ 1] = a.SBoxes[byte1(cols[1])] ^ (uint8_t)(a.Subkeys[i]>>16);
	p[ 2] = a.SBoxes[byte2(cols[2])] ^ (uint8_t)(a.Subkeys[i]>>8);
	p[ 3] = a.SBoxes[byte3(cols[3])] ^ (uint8_t)a.Subkeys[i];

	p[ 4] = a.SBoxes[byte0(cols[1])] ^ (uint8_t)(a.Subkeys[i+1]>>24);
	p[ 5] = a.SBoxes[byte1(cols[2])] ^ (uint8_t)(a.Subkeys[i+1]>>16);
	p[ 6] = a.SBoxes[byte2(cols[3])] ^ (uint8_t)(a.Subkeys[i+1]>>8);
	p[ 7] = a.SBoxes[byte3(cols[0])] ^ (uint8_t)a.Subkeys[i+1];

	p[ 8] = a.SBoxes[byte0(cols[2])] ^ (uint8_t)(a.Subkeys[i+2]>>24);
	p[ 9] = a.SBoxes[byte1(cols[3])] ^ (uint8_t)(a.Subkeys[i+2]>>16);
	p[10] = a.SBoxes[byte2(cols[0])] ^ (uint8_t)(a.Subkeys[i+2]>>8);
	p[11] = a.SBoxes[byte3(cols[1])] ^ (uint8_t)a.Subkeys[i+2];

	p[12] = a.SBoxes[byte0(cols[3])] ^ (uint8_t)(a.Subkeys[i+3]>>24);
	p[13] = a.SBoxes[byte1(cols[0])] ^ (uint8_t)(a.Subkeys[i+3]>>16);
	p[14] = a.SBoxes[byte2(cols[1])] ^ (uint8_t)(a.Subkeys[i+3]>>8);
	p[15] = a.SBoxes[byte3(cols[2])] ^ (uint8_t)a.Subkeys[i+3];
}

/* The last decryption step: AddRoundKey and store. */
FORCE_INLINE void aes_lastInvRound(const uint32_t cols[4], uint8_t *p, const AES &a, int i)
{
	p[ 0] = byte0(cols[0]) ^ (uint8_t)(a.Subkeys[i]>>24);
	p[ 1] = byte1(cols[0]) ^ (uint8_t)(a.Subkeys[i]>>16);
	p[ 2] = byte2(cols[0]) ^ (uint8_t)(a.Subkeys[i]>>8);
	p[ 3] = byte3(cols[0]) ^ (uint8_t)a.Subkeys[i];

	p[ 4] = byte0(cols[1]) ^ (uint8_t)(a.Subkeys[i+1]>>24);
	p[ 5] = byte1(cols[1]) ^ (uint8_t)(a.Subkeys[i+1]>>16);
	p[ 6] = byte2(cols[1]) ^ (uint8_t)(a.Subkeys[i+1]>>8);
	p[ 7] = byte3(cols[1]) ^ (uint8_t)a.Subkeys[i+1];

	p[ 8] = byte0(cols[2]) ^ (uint8_t)(a.Subkeys[i+2]>>24);
	p[ 9] = byte1(cols[2]) ^ (uint8_t)(a.Subkeys[i+2]>>16);
	p[10] = byte2(cols[2]) ^ (uint8_t)(a.Subkeys[i+2]>>8);
	p[11] = byte3(cols[2]) ^ (uint8_t)a.Subkeys[i+2];

	p[12] = byte0(cols[3]) ^ (uint8_t)(a.Subkeys[i+3]>>24);
	p[13] = byte1(cols[3]) ^ (uint8_t)(a.Subkeys[i+3]>>16);
	p[14] = byte2(cols[3]) ^ (uint8_t)(a.Subkeys[i+3]>>8);
	p[15] = byte3(cols[3]) ^ (uint8_t)a.Subkeys[i+3];
}

/* InvMixColumns, through the inverse T-tables. */
FORCE_INLINE void aes_invMixRows(const uint32_t coln1[4], uint32_t coln2[4], const AES &a)
{
	coln2[0] = a.invMixRowCol0[byte0(coln1[0])]^a.invMixRowCol1[byte1(coln1[0])]^a.invMixRowCol2[byte2(coln1[0])]^a.invMixRowCol3[byte3(coln1[0])];
	coln2[1] = a.invMixRowCol0[byte0(coln1[1])]^a.invMixRowCol1[byte1(coln1[1])]^a.invMixRowCol2[byte2(coln1[1])]^a.invMixRowCol3[byte3(coln1[1])];
	coln2[2] = a.invMixRowCol0[byte0(coln1[2])]^a.invMixRowCol1[byte1(coln1[2])]^a.invMixRowCol2[byte2(coln1[2])]^a.invMixRowCol3[byte3(coln1[2])];
	coln2[3] = a.invMixRowCol0[byte0(coln1[3])]^a.invMixRowCol1[byte1(coln1[3])]^a.invMixRowCol2[byte2(coln1[3])]^a.invMixRowCol3[byte3(coln1[3])];
}

/* InvShiftRows and InvSubBytes in one pass. */
FORCE_INLINE void aes_invShiftRowsSB(const uint32_t cols1[4], uint32_t cols2[4], const AES &a)
{
	cols2[0] = ((uint32_t)a.InvSBoxes[byte0(cols1[0])]<<24)|(a.InvSBoxes[byte1(cols1[3])]<<16)|(a.InvSBoxes[byte2(cols1[2])]<<8)|a.InvSBoxes[byte3(cols1[1])];
	cols2[1] = ((uint32_t)a.InvSBoxes[byte0(cols1[1])]<<24)|(a.InvSBoxes[byte1(cols1[0])]<<16)|(a.InvSBoxes[byte2(cols1[3])]<<8)|a.InvSBoxes[byte3(cols1[2])];
	cols2[2] = ((uint32_t)a.InvSBoxes[byte0(cols1[2])]<<24)|(a.InvSBoxes[byte1(cols1[1])]<<16)|(a.InvSBoxes[byte2(cols1[0])]<<8)|a.InvSBoxes[byte3(cols1[3])];
	cols2[3] = ((uint32_t)a.InvSBoxes[byte0(cols1[3])]<<24)|(a.InvSBoxes[byte1(cols1[2])]<<16)|(a.InvSBoxes[byte2(cols1[1])]<<8)|a.InvSBoxes[byte3(cols1[0])];
}

/* One inverse round, in place on col1: AddRoundKey, InvMixColumns, then
   InvShiftRows and InvSubBytes. col2 is scratch. */
FORCE_INLINE void aes_invRound(uint32_t col1[4], uint32_t col2[4], const AES &a, int i)
{
	col1[0] ^= a.Subkeys[4*i];
	col1[1] ^= a.Subkeys[4*i+1];
	col1[2] ^= a.Subkeys[4*i+2];
	col1[3] ^= a.Subkeys[4*i+3];
	aes_invMixRows(col1, col2, a);
	aes_invShiftRowsSB(col2, col1, a);
}



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
		keySet = false;
		/* AES takes a 128, 192 or 256-bit key, i.e. 32, 48 or 64 hex
		   characters. This used to round the length up to the next of those
		   sizes and pad with '0', so a 33-character key silently became a
		   valid AES-192 key containing a '0' the caller never wrote, and
		   anything past 64 characters was truncated. Reject instead. */
		if (key.size() != 32 && key.size() != 48 && key.size() != 64)
			throw std::invalid_argument("AES key must be 16, 24 or 32 bytes, got " + std::to_string(key.size() / 2));

		int N = key.length()/8;
		int R = 1;
		if (N == 4)
			R = 11;
		if (N == 6)
			R = 13;
		if (N == 8)
			R = 15;

		std::vector<std::vector<uint8_t>> W;
		for(int i=0; i<(int)key.length();i = i+8){
			W.push_back({(uint8_t)std::stoul(key.substr(i,2), 0, 16),
						(uint8_t)std::stoul(key.substr(i+2,2), 0, 16),
						(uint8_t)std::stoul(key.substr(i+4,2), 0, 16),
						(uint8_t)std::stoul(key.substr(i+6,2), 0, 16) });
		}
			
		uint8_t rcon[4] = {1, 0, 0, 0};
		std::vector<uint8_t> temp;
		for (int x = N; x<4*R; ++x){
			temp = W[x-1];
			if (x % N == 0){
				if (x-N > 0){
					if (rcon[0] < 128){
						rcon[0] = 2*rcon[0];
					}else{
						rcon[0] = (2*rcon[0])^0x11B;
					}
				}
				aes_rotl4(temp.data());
				aes_subBytes4(temp.data(), SBoxes);
				aes_xor4(temp.data(), rcon);
				aes_xor4(temp, W[x - N]);
				W.push_back(temp);
			}else if (N > 6 && x % N == 4){
				aes_subBytes4(temp.data(), SBoxes);
				aes_xor4(temp, W[x - N]);
				W.push_back(temp);
			}
			else{
				aes_xor4(temp, W[x - N]);
				W.push_back(temp);
			}
		}
		Subkeys.clear();
		for (int i=0;i<4*R;++i)
			Subkeys.push_back(((uint32_t)W[i][0]<<24)|((uint32_t)W[i][1]<<16)|((uint32_t)W[i][2]<<8)|W[i][3] );
		keySet = true;
		
		
	}

	void AES::encrypt_block128(uint8_t *p) const
	{	
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		aes_firstRound(columnA, p, *this, 0);
		aes_round(columnA, columnB, *this, 1);
		aes_round(columnB, columnA, *this, 2);
		aes_round(columnA, columnB, *this, 3);
		aes_round(columnB, columnA, *this, 4);
		aes_round(columnA, columnB, *this, 5);
		aes_round(columnB, columnA, *this, 6);
		aes_round(columnA, columnB, *this, 7);
		aes_round(columnB, columnA, *this, 8);
		aes_round(columnA, columnB, *this, 9);
		aes_lastRound(columnB, p, *this, 40);
	}

	void AES::encrypt_block192(uint8_t *p) const
	{	
		uint32_t columnA[4];
		uint32_t columnB[4];

		aes_firstRound(columnA, p, *this, 0);
		aes_round(columnA, columnB, *this, 1);
		aes_round(columnB, columnA, *this, 2);
		aes_round(columnA, columnB, *this, 3);
		aes_round(columnB, columnA, *this, 4);
		aes_round(columnA, columnB, *this, 5);
		aes_round(columnB, columnA, *this, 6);
		aes_round(columnA, columnB, *this, 7);
		aes_round(columnB, columnA, *this, 8);
		aes_round(columnA, columnB, *this, 9);
		aes_round(columnB, columnA, *this, 10);
		aes_round(columnA, columnB, *this, 11);
		aes_lastRound(columnB, p, *this, 48);
	}

	void AES::encrypt_block256(uint8_t *p) const
	{	
		uint32_t columnA[4];
		uint32_t columnB[4];

		aes_firstRound(columnA, p, *this, 0);
		aes_round(columnA, columnB, *this, 1);
		aes_round(columnB, columnA, *this, 2);
		aes_round(columnA, columnB, *this, 3);
		aes_round(columnB, columnA, *this, 4);
		aes_round(columnA, columnB, *this, 5);
		aes_round(columnB, columnA, *this, 6);
		aes_round(columnA, columnB, *this, 7);
		aes_round(columnB, columnA, *this, 8);
		aes_round(columnA, columnB, *this, 9);
		aes_round(columnB, columnA, *this, 10);
		aes_round(columnA, columnB, *this, 11);
		aes_round(columnB, columnA, *this, 12);
		aes_round(columnA, columnB, *this, 13);
		aes_lastRound(columnB, p, *this, 56);
	}

	void AES::decrypt_block128(uint8_t *p) const
	{	
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		aes_firstRound(columnB, p, *this, 40);
		aes_invShiftRowsSB(columnB, columnA, *this);
		aes_invRound(columnA, columnB, *this, 9);
		aes_invRound(columnA, columnB, *this, 8);
		aes_invRound(columnA, columnB, *this, 7);
		aes_invRound(columnA, columnB, *this, 6);
		aes_invRound(columnA, columnB, *this, 5);
		aes_invRound(columnA, columnB, *this, 4);
		aes_invRound(columnA, columnB, *this, 3);
		aes_invRound(columnA, columnB, *this, 2);
		aes_invRound(columnA, columnB, *this, 1);
		aes_lastInvRound(columnA, p, *this, 0);
	}


	void AES::decrypt_block192(uint8_t *p) const
	{	
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		aes_firstRound(columnB, p, *this, 48);
		aes_invShiftRowsSB(columnB, columnA, *this);
		aes_invRound(columnA, columnB, *this, 11);
		aes_invRound(columnA, columnB, *this, 10);
		aes_invRound(columnA, columnB, *this, 9);
		aes_invRound(columnA, columnB, *this, 8);
		aes_invRound(columnA, columnB, *this, 7);
		aes_invRound(columnA, columnB, *this, 6);
		aes_invRound(columnA, columnB, *this, 5);
		aes_invRound(columnA, columnB, *this, 4);
		aes_invRound(columnA, columnB, *this, 3);
		aes_invRound(columnA, columnB, *this, 2);
		aes_invRound(columnA, columnB, *this, 1);
		aes_lastInvRound(columnA, p, *this, 0);
	}

void AES::decrypt_block256(uint8_t *p) const
	{	
		uint32_t columnA[4];
		uint32_t columnB[4];
		
		aes_firstRound(columnB, p, *this, 56);
		aes_invShiftRowsSB(columnB, columnA, *this);
		aes_invRound(columnA, columnB, *this, 13);
		aes_invRound(columnA, columnB, *this, 12);
		aes_invRound(columnA, columnB, *this, 11);
		aes_invRound(columnA, columnB, *this, 10);
		aes_invRound(columnA, columnB, *this, 9);
		aes_invRound(columnA, columnB, *this, 8);
		aes_invRound(columnA, columnB, *this, 7);
		aes_invRound(columnA, columnB, *this, 6);
		aes_invRound(columnA, columnB, *this, 5);
		aes_invRound(columnA, columnB, *this, 4);
		aes_invRound(columnA, columnB, *this, 3);
		aes_invRound(columnA, columnB, *this, 2);
		aes_invRound(columnA, columnB, *this, 1);
		aes_lastInvRound(columnA, p, *this, 0);
	}



	size_t AES::blockSize() const noexcept
	{
		return 16;
	}

	void AES::encryptBlock(uint8_t *block) const
	{
		requireKey();
		switch(Subkeys.size())
		{
			case 60: encrypt_block256(block); break;
			case 52: encrypt_block192(block); break;
			case 44: encrypt_block128(block); break;
		}
	}

	void AES::decryptBlock(uint8_t *block) const
	{
		requireKey();
		switch(Subkeys.size())
		{
			case 60: decrypt_block256(block); break;
			case 52: decrypt_block192(block); break;
			case 44: decrypt_block128(block); break;
		}
	}

	std::vector<uint8_t> AES::encrypt(std::span<const uint8_t> plt) const
	{
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

	std::vector<uint8_t> AES::decrypt(std::span<const uint8_t> plt) const
	{
		return decryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

} // namespace block
