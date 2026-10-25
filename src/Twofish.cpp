#include <vector>
#include <stdexcept>

#include "block/Twofish.h"
#include <iterator>
#include "Twofish_data.h"
#include "force_inline.h"

Twofish::Twofish()
{
	RS.clear();
	for (const auto& r : RS_data) RS.emplace_back(std::begin(r), std::end(r));
	MDS.clear();
	for (const auto& r : MDS_data) MDS.emplace_back(std::begin(r), std::end(r));
	MDSEF.assign(std::begin(MDSEF_data), std::end(MDSEF_data));
	MDS5B.assign(std::begin(MDS5B_data), std::end(MDS5B_data));
	q0.assign(std::begin(q0_data), std::end(q0_data));
	q1.assign(std::begin(q1_data), std::end(q1_data));
}







/* Pseudo-Hadamard transform: a' = a + b, b' = a + 2b. */
FORCE_INLINE void twofish_pht(uint32_t *a, uint32_t *b)
{
	uint32_t t = *a;
	*a = *a + *b;
	*b = t + (*b << 1);
}

/* Multiplies the four bytes of t by the MDS matrix. */
FORCE_INLINE uint32_t twofish_mds(const Twofish &tf, uint32_t t)
{
	return (uint32_t)(BlockCipher::byte3(t) ^ tf.MDSEF[BlockCipher::byte2(t)] ^ tf.MDS5B[BlockCipher::byte1(t)] ^ tf.MDS5B[BlockCipher::byte0(t)])
		| ((uint32_t)(tf.MDS5B[BlockCipher::byte3(t)] ^ tf.MDSEF[BlockCipher::byte2(t)] ^ tf.MDSEF[BlockCipher::byte1(t)] ^ BlockCipher::byte0(t)) << 8)
		| ((uint32_t)(tf.MDSEF[BlockCipher::byte3(t)] ^ tf.MDS5B[BlockCipher::byte2(t)] ^ BlockCipher::byte1(t) ^ tf.MDSEF[BlockCipher::byte0(t)]) << 16)
		| ((uint32_t)(tf.MDSEF[BlockCipher::byte3(t)] ^ BlockCipher::byte2(t) ^ tf.MDSEF[BlockCipher::byte1(t)] ^ tf.MDS5B[BlockCipher::byte0(t)]) << 24);
}

/* The h function for 128, 192 and 256-bit keys: the q-permutation chain for
   that key length, followed by the MDS multiply. Only the key schedule uses
   it; encryption goes through the precomputed Sbox0..3 tables instead. */
static uint32_t twofish_h128(uint32_t x, const uint8_t *k, const Twofish &tf)
{
	uint32_t t = (uint32_t)tf.q1[tf.q0[tf.q0[BlockCipher::byte0(x)] ^ k[0]] ^ k[4]]
		| ((uint32_t)tf.q0[tf.q0[tf.q1[BlockCipher::byte1(x)] ^ k[1]] ^ k[5]] << 8)
		| ((uint32_t)tf.q1[tf.q1[tf.q0[BlockCipher::byte2(x)] ^ k[2]] ^ k[6]] << 16)
		| ((uint32_t)tf.q0[tf.q1[tf.q1[BlockCipher::byte3(x)] ^ k[3]] ^ k[7]] << 24);
	return twofish_mds(tf, t);
}

static uint32_t twofish_h192(uint32_t x, const uint8_t *k, const Twofish &tf)
{
	uint32_t t = (uint32_t)tf.q1[tf.q0[tf.q0[tf.q1[BlockCipher::byte0(x)] ^ k[0]] ^ k[4]] ^ k[8]]
		| ((uint32_t)tf.q0[tf.q0[tf.q1[tf.q1[BlockCipher::byte1(x)] ^ k[1]] ^ k[5]] ^ k[9]] << 8)
		| ((uint32_t)tf.q1[tf.q1[tf.q0[tf.q0[BlockCipher::byte2(x)] ^ k[2]] ^ k[6]] ^ k[10]] << 16)
		| ((uint32_t)tf.q0[tf.q1[tf.q1[tf.q0[BlockCipher::byte3(x)] ^ k[3]] ^ k[7]] ^ k[11]] << 24);
	return twofish_mds(tf, t);
}

static uint32_t twofish_h256(uint32_t x, const uint8_t *k, const Twofish &tf)
{
	uint32_t t = (uint32_t)tf.q1[tf.q0[tf.q0[tf.q1[tf.q1[BlockCipher::byte0(x)] ^ k[0]] ^ k[4]] ^ k[8]] ^ k[12]]
		| ((uint32_t)tf.q0[tf.q0[tf.q1[tf.q1[tf.q0[BlockCipher::byte1(x)] ^ k[1]] ^ k[5]] ^ k[9]] ^ k[13]] << 8)
		| ((uint32_t)tf.q1[tf.q1[tf.q0[tf.q0[tf.q0[BlockCipher::byte2(x)] ^ k[2]] ^ k[6]] ^ k[10]] ^ k[14]] << 16)
		| ((uint32_t)tf.q0[tf.q1[tf.q1[tf.q0[tf.q1[BlockCipher::byte3(x)] ^ k[3]] ^ k[7]] ^ k[11]] ^ k[15]] << 24);
	return twofish_mds(tf, t);
}

/* The g function, through the key-dependent S-boxes built by the schedule. */
FORCE_INLINE uint32_t twofish_g(const Twofish *tf, uint32_t x)
{
	return tf->Sbox0[BlockCipher::byte0(x)] ^ tf->Sbox1[BlockCipher::byte1(x)] ^ tf->Sbox2[BlockCipher::byte2(x)] ^ tf->Sbox3[BlockCipher::byte3(x)];
}

/* One encryption round: F of the half (l0, l1) is mixed with (r0, r1) into
   (nl0, nl1). Calling it with the halves rotated on alternate rounds gives the
   Feistel swap without moving any data. */
FORCE_INLINE void twofish_round(int i, uint32_t l0, uint32_t l1, uint32_t r0, uint32_t r1, uint32_t &nl0, uint32_t &nl1, const Twofish *tf)
{
	uint32_t t0 = twofish_g(tf, l0);
	uint32_t t1 = twofish_g(tf, BlockCipher::rotl(l1, 8));
	twofish_pht(&t0, &t1);
	t0 += tf->Subkeys[2*i+8];
	t1 += tf->Subkeys[2*i+9];
	nl0 = BlockCipher::rotr(t0 ^ r0, 1);
	nl1 = t1 ^ BlockCipher::rotl(r1, 1);
}

/* The inverse round: the same F, with the rotations of the mixing step undone. */
FORCE_INLINE void twofish_invRound(int i, uint32_t l0, uint32_t l1, uint32_t r0, uint32_t r1, uint32_t &nl0, uint32_t &nl1, const Twofish *tf)
{
	uint32_t t0 = twofish_g(tf, l0);
	uint32_t t1 = twofish_g(tf, BlockCipher::rotl(l1, 8));
	twofish_pht(&t0, &t1);
	t0 += tf->Subkeys[2*i+8];
	t1 += tf->Subkeys[2*i+9];
	nl0 = t0 ^ BlockCipher::rotl(r0, 1);
	nl1 = BlockCipher::rotr(t1 ^ r1, 1);
}
	uint32_t Twofish::multgf(uint32_t a,uint32_t b,uint32_t pol) const {
		if (b == 0 )
			return 0L;
		uint32_t p = 0;
		while (b != 0){
			if (b%2L == 1)
				p = p^a;
			b = b>>1;
			a = a<<1;
			if (a > 255)
				a = a^pol;			
		}
		return p;
	}

	uint8_t Twofish::multgf(uint16_t a,uint16_t b) const {
		if (b == 0 )
			return (uint8_t)0;
		uint16_t p = 0;
		while (b != 0){
			if (b&1)
				p = p^a;
			b = b>>1;
			a = a<<1;
			if (a > 255)
				a = a^333;			
		}
		return (uint8_t)p;
	}

	uint8_t Twofish::RSAmul(int i, const uint8_t *p) const
	{
		uint8_t result = 0;
		for (int t = 0; t < 8; ++t)
			result ^= multgf((uint16_t)*(p+t),(uint16_t)RS[i][t]);
		return result;
	}

	void Twofish::generateKeys(const std::vector<uint8_t>& key)
	{
		keySet = false;
		if (key.size() != 16 && key.size() != 24 && key.size() != 32)
			throw std::invalid_argument("Twofish key must be 16, 24 or 32 bytes, got " + std::to_string(key.size()));

		int n = (int)key.size();

		std::vector<uint8_t> S;
		for (int i = 0; i < n; i = i + 8)
		{
			S.push_back(RSAmul(0, &key[i]));
			S.push_back(RSAmul(1, &key[i]));
			S.push_back(RSAmul(2, &key[i]));
			S.push_back(RSAmul(3, &key[i]));
		}

		uint8_t s0 = 0;
		uint8_t s1 = 0;
		uint8_t s2 = 0;
		uint8_t s3 = 0;

		Sbox0.clear();
		Sbox1.clear();
		Sbox2.clear();
		Sbox3.clear();

		for (int i = 0; i < 256; ++i)
		{
			switch (n / 8)
			{
				case 4:
					s0 = q1[q0[q0[q1[q1[i]^S[0]]^S[4]]^S[8]]^S[12]];
					s1 = q0[q0[q1[q1[q0[i]^S[1]]^S[5]]^S[9]]^S[13]];
					s2 = q1[q1[q0[q0[q0[i]^S[2]]^S[6]]^S[10]]^S[14]];
					s3 = q0[q1[q1[q0[q1[i]^S[3]]^S[7]]^S[11]]^S[15]];
					break;
				case 3:
					s0 = q1[q0[q0[q1[i]^S[0]]^S[4]]^S[8]];
					s1 = q0[q0[q1[q1[i]^S[1]]^S[5]]^S[9]];
					s2 = q1[q1[q0[q0[i]^S[2]]^S[6]]^S[10]];
					s3 = q0[q1[q1[q0[i]^S[3]]^S[7]]^S[11]];
					break;
				case 2:
					s0 = q1[q0[q0[i]^S[0]]^S[4]];
					s1 = q0[q0[q1[i]^S[1]]^S[5]];
					s2 = q1[q1[q0[i]^S[2]]^S[6]];
					s3 = q0[q1[q1[i]^S[3]]^S[7]];
					break;
			}

			Sbox3.push_back(s0 |((uint32_t)MDS5B[s0]<<8)|((uint32_t)MDSEF[s0]<<16)|((uint32_t)MDSEF[s0]<<24));
			Sbox2.push_back(MDSEF[s1]|((uint32_t)MDSEF[s1]<<8)|((uint32_t)MDS5B[s1]<<16)|((uint32_t)s1<<24));
			Sbox1.push_back(MDS5B[s2]|((uint32_t)MDSEF[s2]<<8)|((uint32_t)s2<<16)|((uint32_t)MDSEF[s2]<<24));
			Sbox0.push_back(MDS5B[s3]|((uint32_t)s3<<8)|((uint32_t)MDSEF[s3]<<16)|((uint32_t)MDS5B[s3]<<24));
		}

		std::vector<uint8_t> M_odd(n/2, 0);
		std::vector<uint8_t> M_even(n/2, 0);
		int i_even = 0;
		int i_odd = 0;
		for (int i = 0;i < n; i = i+4){
			if ((i/4)%2 == 1){
				M_odd[n/2-i_odd-4] = key[i];
				M_odd[n/2-i_odd-3] = key[i+1];
				M_odd[n/2-i_odd-2] = key[i+2];
				M_odd[n/2-i_odd-1] = key[i+3];
				i_odd += 4;
			}else{
				M_even[n/2-i_even-4] = key[i];
				M_even[n/2-i_even-3] = key[i+1];
				M_even[n/2-i_even-2] = key[i+2];
				M_even[n/2-i_even-1] = key[i+3];
				i_even += 4;
			}
		}

		
				
		uint32_t rho = 16843009;//2**24+2**16+2**8+1
		uint32_t a0, b0;
		Subkeys.clear();
		for (int i = 0 ; i < 20; ++i){
			a0 = 2*i*rho;
			b0 = (2*i+1)*rho;
			switch (n/8){
				case 4:
					a0 = twofish_h256(a0, &M_even[0], *this);
					b0 = twofish_h256(b0, &M_odd[0], *this);
					break;
				case 3:
					a0 = twofish_h192(a0, &M_even[0], *this);
					b0 = twofish_h192(b0, &M_odd[0], *this);
					break;
				case 2:
					a0 = twofish_h128(a0, &M_even[0], *this);
					b0 = twofish_h128(b0, &M_odd[0], *this);
					break;
			}
			b0 = BlockCipher::rotl(b0,8);
			twofish_pht(&a0, &b0);
			Subkeys.push_back(a0);
			b0 = BlockCipher::rotl(b0,9);
			Subkeys.push_back(b0);	 
		}
		keySet = true;
	}

	void Twofish::encryptBlock(uint8_t *block) const
	{
		requireKey();
		uint32_t left0 = BlockCipher::load32_le(block) ^ Subkeys[0];
		uint32_t left1 = BlockCipher::load32_le(block + 4) ^ Subkeys[1];
		uint32_t right0 = BlockCipher::load32_le(block + 8) ^ Subkeys[2];
		uint32_t right1 = BlockCipher::load32_le(block + 12) ^ Subkeys[3];
		uint32_t newl0, newl1;

		twofish_round( 0, left0, left1, right0, right1, newl0, newl1, this);
		twofish_round( 1, newl0, newl1, left0, left1, right0, right1, this);
		twofish_round( 2, right0, right1, newl0, newl1, left0, left1, this);
		twofish_round( 3, left0, left1, right0, right1, newl0, newl1, this);
		twofish_round( 4, newl0, newl1, left0, left1, right0, right1, this);
		twofish_round( 5, right0, right1, newl0, newl1, left0, left1, this);
		twofish_round( 6, left0, left1, right0, right1, newl0, newl1, this);
		twofish_round( 7, newl0, newl1, left0, left1, right0, right1, this);
		twofish_round( 8, right0, right1, newl0, newl1, left0, left1, this);
		twofish_round( 9, left0, left1, right0, right1, newl0, newl1, this);
		twofish_round(10, newl0, newl1, left0, left1, right0, right1, this);
		twofish_round(11, right0, right1, newl0, newl1, left0, left1, this);
		twofish_round(12, left0, left1, right0, right1, newl0, newl1, this);
		twofish_round(13, newl0, newl1, left0, left1, right0, right1, this);
		twofish_round(14, right0, right1, newl0, newl1, left0, left1, this);
		twofish_round(15, left0, left1, right0, right1, newl0, newl1, this);

		left0 ^= Subkeys[4]; left1 ^= Subkeys[5];
		newl0 ^= Subkeys[6]; newl1 ^= Subkeys[7];

		BlockCipher::store32_le(block, left0);
		BlockCipher::store32_le(block + 4, left1);
		BlockCipher::store32_le(block + 8, newl0);
		BlockCipher::store32_le(block + 12, newl1);
	}

	void Twofish::decryptBlock(uint8_t *block) const
	{
		requireKey();
		uint32_t left0 = BlockCipher::load32_le(block) ^ Subkeys[4];
		uint32_t left1 = BlockCipher::load32_le(block + 4) ^ Subkeys[5];
		uint32_t right0 = BlockCipher::load32_le(block + 8) ^ Subkeys[6];
		uint32_t right1 = BlockCipher::load32_le(block + 12) ^ Subkeys[7];
		uint32_t newl0, newl1;

		twofish_invRound(15, left0, left1, right0, right1, newl0, newl1, this);
		twofish_invRound(14, newl0, newl1, left0, left1, right0, right1, this);
		twofish_invRound(13, right0, right1, newl0, newl1, left0, left1, this);
		twofish_invRound(12, left0, left1, right0, right1, newl0, newl1, this);
		twofish_invRound(11, newl0, newl1, left0, left1, right0, right1, this);
		twofish_invRound(10, right0, right1, newl0, newl1, left0, left1, this);
		twofish_invRound( 9, left0, left1, right0, right1, newl0, newl1, this);
		twofish_invRound( 8, newl0, newl1, left0, left1, right0, right1, this);
		twofish_invRound( 7, right0, right1, newl0, newl1, left0, left1, this);
		twofish_invRound( 6, left0, left1, right0, right1, newl0, newl1, this);
		twofish_invRound( 5, newl0, newl1, left0, left1, right0, right1, this);
		twofish_invRound( 4, right0, right1, newl0, newl1, left0, left1, this);
		twofish_invRound( 3, left0, left1, right0, right1, newl0, newl1, this);
		twofish_invRound( 2, newl0, newl1, left0, left1, right0, right1, this);
		twofish_invRound( 1, right0, right1, newl0, newl1, left0, left1, this);
		twofish_invRound( 0, left0, left1, right0, right1, newl0, newl1, this);

		left0 ^= Subkeys[0]; left1 ^= Subkeys[1];
		newl0 ^= Subkeys[2]; newl1 ^= Subkeys[3];

		BlockCipher::store32_le(block, left0);
		BlockCipher::store32_le(block + 4, left1);
		BlockCipher::store32_le(block + 8, newl0);
		BlockCipher::store32_le(block + 12, newl1);
	}

	

	
	int Twofish::blockSize() const
	{
		return 16;
	}

	std::vector<uint8_t> Twofish::encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const
	{
		return encryptMode(plt, BlockMode::CBC, Padding::PKCS7, iv);
	}
