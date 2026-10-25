#include <vector>
#include <string>
#include <stdexcept>

#include "block/Serpent.h"
#include <iterator>
#include "Serpent_data.h"
#include "bits.h"
#include "force_inline.h"

namespace block {

using namespace detail;

Serpent::Serpent()
{
	SBox.clear();
	for (const auto& r : SBox_data) SBox.emplace_back(std::begin(r), std::end(r));
	invSBox.clear();
	for (const auto& r : invSBox_data) invSBox.emplace_back(std::begin(r), std::end(r));
}


/* The block is held as four 32-bit words in little-endian bit order, so the
   paper's "<<<" and "<<" (Serpent proposal, Section 3) are plain rotl and
   masked left shifts on those words. */

/* The ten steps of the paper's linear transformation, in its order. */
FORCE_INLINE void serpent_LT(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3)
{
	*x0 = rotl(*x0, 13);
	*x2 = rotl(*x2, 3);
	*x1 = *x1 ^ *x0 ^ *x2;
	*x3 = *x3 ^ *x2 ^ (*x0 << 3);
	*x1 = rotl(*x1, 1);
	*x3 = rotl(*x3, 7);
	*x0 = *x0 ^ *x1 ^ *x3;
	*x2 = *x2 ^ *x3 ^ (*x1 << 7);
	*x0 = rotl(*x0, 5);
	*x2 = rotl(*x2, 22);
}

/* The same ten steps in reverse order, with every rotation turned around. */
FORCE_INLINE void serpent_invLT(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3)
{
	*x2 = rotr(*x2, 22);
	*x0 = rotr(*x0, 5);
	*x2 = *x2 ^ *x3 ^ (*x1 << 7);
	*x0 = *x0 ^ *x1 ^ *x3;
	*x3 = rotr(*x3, 7);
	*x1 = rotr(*x1, 1);
	*x3 = *x3 ^ *x2 ^ (*x0 << 3);
	*x1 = *x1 ^ *x0 ^ *x2;
	*x2 = rotr(*x2, 3);
	*x0 = rotr(*x0, 13);
}

FORCE_INLINE void serpent_addRoundKey(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int i, const Serpent *s)
{
	*x0 ^= s->Subkeys[(i<<2)];
	*x1 ^= s->Subkeys[(i<<2)+1];
	*x2 ^= s->Subkeys[(i<<2)+2];
	*x3 ^= s->Subkeys[(i<<2)+3];
}

/* Rounds 0 to 30: key mixing, S-box i mod 8, linear transformation. */
FORCE_INLINE void serpent_round(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int i, const Serpent *s)
{
	serpent_addRoundKey(x0, x1, x2, x3, i, s);
	s->applySBox(x0, x1, x2, x3, i%8);
	serpent_LT(x0, x1, x2, x3);
}

/* The inverse round: the same steps in reverse, with the S-box inverted. */
FORCE_INLINE void serpent_invRound(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int i, const Serpent *s)
{
	serpent_invLT(x0, x1, x2, x3);
	s->applyInvSBox(x0, x1, x2, x3, i%8);
	serpent_addRoundKey(x0, x1, x2, x3, i, s);
}

	static std::string padKeyBit(std::string key)
	{
		if (key.empty())
			key = "00";
		if (key.size() % 2 == 1)
			key += "0";
		if ((int)key.size() >= 64)
			return key.substr(0, 64);
		std::string bin;
		for (size_t i = 0; i < key.size(); ++i)
		{
			uint8_t v = (uint8_t)std::stoul(key.substr(i,1), 0, 16);
			for (int b = 3; b >= 0; --b)
				bin += ((v>>b)&1) ? '1' : '0';
		}
// The spec pads short keys by appending a '1' bit, i.e. a byte
		// of 0x01 right after the key bytes.
		bin += "00000001";
	while ((int)bin.size() < 256)
	{
		bin += '0';
	}
		std::string out;
		for (int i = 0; i < 256; i += 4)
		{
			int v = ((bin[i]-'0')<<3)|((bin[i+1]-'0')<<2)|((bin[i+2]-'0')<<1)|(bin[i+3]-'0');
			out += "0123456789abcdef"[v];
		}
		return out;
	}


/* Word and byte conversion follow Serpent's bit order (Section 3.3): the first
   bit of the block is the least significant bit of word 0, so the four bytes of
   a word are read and written little-endian and left unreversed. */
static uint32_t serpentLoad32(const uint8_t *p)
{
	return (uint32_t)p[0]
		| ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16)
		| ((uint32_t)p[3] << 24);
}

static void serpentStore32(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)(w);
	p[1] = (uint8_t)(w >> 8);
	p[2] = (uint8_t)(w >> 16);
	p[3] = (uint8_t)(w >> 24);
}

/* The same little-endian word, read from eight hex characters. */
static uint32_t serpentWordFromHex(const std::string &s)
{
	uint32_t result = 0;
	for (int i = 0; i < 4; ++i)
		result |= (uint32_t)std::stoul(s.substr(2 * i, 2), 0, 16) << (8 * i);
	return result;
}

	void Serpent::applySBox(uint32_t *x0,uint32_t *x1,uint32_t *x2, uint32_t *x3, int n) const{
        uint32_t r0 = *x0;
        uint32_t r1 = *x1;
        uint32_t r2 = *x2;
        uint32_t r3 = *x3;
        uint32_t r4 = 0;
        switch (n) {
            case 0:
                r3 ^= r0;
                r4 = r1;
                r1 &= r3;
                r4 ^= r2;
                r1 ^= r0;
                r0 |= r3;
                r0 ^= r4;
                r4 ^= r3;
                r3 ^= r2;
                r2 |= r1;
                r2 ^= r4;
                r4 ^= 0xffffffff;
                r4 |= r1;
                r1 ^= r3;
                r1 ^= r4;
                r3 |= r0;
                r1 ^= r3;
                r4 ^= r3;
                
                *x0 = r1;
                *x1 = r4;
                *x2 = r2;
                *x3 = r0;
                return;

             case 1:
                r0 ^= 0xffffffff;
                r2 ^= 0xffffffff;
                r4 = r0;
                r0 &= r1;
                r2 ^= r0;
                r0 |= r3;
                r3 ^= r2;
                r1 ^= r0;
                r0 ^= r4;
                r4 |= r1;
                r1 ^= r3;
                r2 |= r0;
                r2 &= r4;
                r0 ^= r1;
                r1 &= r2;
                r1 ^= r0;
                r0 &= r2;
                r0 ^= r4;
                
                *x0 = r2;
                *x1 = r0;
                *x2 = r3;
                *x3 = r1;
                return;

            case 2:
                r4 = r0;
                r0 &= r2;
                r0 ^= r3;
                r2 ^= r1;
                r2 ^= r0;
                r3 |= r4;
                r3 ^= r1;
                r4 ^= r2;
                r1 = r3;
                r3 |= r4;
                r3 ^= r0;
                r0 &= r1;
                r4 ^= r0;
                r1 ^= r3;
                r1 ^= r4;
                r4 ^= 0xffffffff;
                
                *x0 = r2;
                *x1 = r3;
                *x2 = r1;
                *x3 = r4;
                return;

            case 3:
                r4 = r0;
                r0 |= r3;
                r3 ^= r1;
                r1 &= r4;
                r4 ^= r2;
                r2 ^= r3;
                r3 &= r0;
                r4 |= r1;
                r3 ^= r4;
                r0 ^= r1;
                r4 &= r0;
                r1 ^= r3;
                r4 ^= r2;
                r1 |= r0;
                r1 ^= r2;
                r0 ^= r3;
                r2 = r1;
                r1 |= r3;
                r1 ^= r0;
                
                *x0 = r1;
                *x1 = r2;
                *x2 = r3;
                *x3 = r4;
                return;

            case 4:
                r1 ^= r3;
                r3 ^= 0xffffffff;
                r2 ^= r3;
                r3 ^= r0;
                r4 = r1;
                r1 &= r3;
                r1 ^= r2;
                r4 ^= r3;
                r0 ^= r4;
                r2 &= r4;
                r2 ^= r0;
                r0 &= r1;
                r3 ^= r0;
                r4 |= r1;
                r4 ^= r0;
                r0 |= r3;
                r0 ^= r2;
                r2 &= r3;
                r0 ^= 0xffffffff;
                r4 ^= r2;
                
                *x0 = r1;
                *x1 = r4;
                *x2 = r0;
                *x3 = r3;
                return;

            case 5:
                r0 ^= r1;
                r1 ^= r3;
                r3 ^= 0xffffffff;
                r4 = r1;
                r1 &= r0;
                r2 ^= r3;
                r1 ^= r2;
                r2 |= r4;
                r4 ^= r3;
                r3 &= r1;
                r3 ^= r0;
                r4 ^= r1;
                r4 ^= r2;
                r2 ^= r0;
                r0 &= r3;
                r2 ^= 0xffffffff;
                r0 ^= r4;
                r4 |= r3;
                r2 ^= r4;
                
                *x0 = r1;
                *x1 = r3;
                *x2 = r0;
                *x3 = r2;
                return;

            case 6:
                r2 ^= 0xffffffff;
                r4 = r3;
                r3 &= r0;
                r0 ^= r4;
                r3 ^= r2;
                r2 |= r4;
                r1 ^= r3;
                r2 ^= r0;
                r0 |= r1;
                r2 ^= r1;
                r4 ^= r0;
                r0 |= r3;
                r0 ^= r2;
                r4 ^= r3;
                r4 ^= r0;
                r3 ^= 0xffffffff;
                r2 &= r4;
                r2 ^= r3;
                
                *x0 = r0;
                *x1 = r1;
                *x2 = r4;
                *x3 = r2;
                return;

            case 7:
                r4 = r1;
                r1 |= r2;
                r1 ^= r3;
                r4 ^= r2;
                r2 ^= r1;
                r3 |= r4;
                r3 &= r0;
                r4 ^= r2;
                r3 ^= r1;
                r1 |= r4;
                r1 ^= r0;
                r0 |= r4;
                r0 ^= r2;
                r1 ^= r4;
                r2 ^= r1;
                r1 &= r0;
                r1 ^= r4;
                r2 ^= 0xffffffff;
                r2 |= r0;
                r4 ^= r2;
                
                *x0 = r4;
                *x1 = r3;
                *x2 = r1;
                *x3 = r0;
                return;
        }
    }

	void Serpent::applyInvSBox(uint32_t *x0,uint32_t *x1,uint32_t *x2, uint32_t *x3, int n) const{
        uint32_t nx0 = 0;
        uint32_t nx1 = 0;
        uint32_t nx2 = 0;
        uint32_t nx3 = 0;

        for (int x = 0; x < 32; ++x)
        {
            uint8_t newbits = invSBox[n][(((*x0>>x)&1) <<0 |
                                          ((*x1>>x)&1) <<1 |
                                          ((*x2>>x)&1) <<2 |
                                          ((*x3>>x)&1) <<3 )];
            nx0 |= ((newbits >> 0)&1) << x;
            nx1 |= ((newbits >> 1)&1) << x;
            nx2 |= ((newbits >> 2)&1) << x;
            nx3 |= ((newbits >> 3)&1) << x;
        }

        *x0 = nx0;
        *x1 = nx1;
        *x2 = nx2;
        *x3 = nx3;
    }

	void Serpent::generateKeys(std::string key)
	{
    keySet = false;
    /* Serpent's specification accepts any key of 1 to 256 bits and defines the
       padding for shorter ones, which padKeyBit below implements, so a short
       key is legal rather than an error. Only the two cases padKeyBit would
       paper over are refused: the empty key, which it turns into "00", and an
       over-long one, which it truncates to 64 characters without saying so.
       The limit is in hex characters, since that is what the key is here. */
    if (key.empty() || key.size() > 64)
        throw std::invalid_argument("Serpent key must be 1 to 32 bytes, got "
                                    + std::to_string((key.size() + 1) / 2));
    key = padKeyBit(key);
    uint32_t wi;
    uint32_t w[140];

    for (int i = 0; i<64; i = i + 8)
    {
      w[i/8] = serpentWordFromHex(key.substr(i,8));
    }

    /* Prekey recurrence (Section 4):
         w_i := (w_i-8 ^ w_i-5 ^ w_i-3 ^ w_i-1 ^ PHI ^ i) <<< 11
       with PHI the fractional part of the golden ratio, 0x9E3779B9. The eight
       key words are w_-8 .. w_-1, so w[8] holds w_0. */
    for(int i=8; i< 140;++i){
      wi = w[i - 8]^ w[i - 5]^ w[i - 3]^ w[i - 1]^ 0x9E3779B9u ^ (uint32_t)(i - 8);
      wi = rotl(wi,11);
      w[i] = wi;
     }
     /* Subkey i is prekeys 4i .. 4i+3 through S-box (3 - i) mod 8, which is the
        S3, S2, S1, S0, S7, S6, S5, S4 order listed in Section 4. C++'s % keeps
        the sign of the dividend, so the double modulo keeps the index in 0..7. */
     for (int i=0;i<33;++i)
     {
            applySBox(&w[4*i+8],&w[4*i+1+8],&w[4*i+2+8],&w[4*i+3+8],((3 - i) % 8 + 8) % 8);
     }        
        Subkeys.clear();
        for (uint32_t *i = &w[0]+8; i < &w[0]+140; ++i)
        {
        	Subkeys.push_back(*i);
        }
        keySet = true;

    }

	void Serpent::encrypt_block(uint8_t *x0,uint8_t *x1,uint8_t *x2,uint8_t *x3) const
	{
			uint32_t w0 = serpentLoad32(x0);
			uint32_t w1 = serpentLoad32(x1);
			uint32_t w2 = serpentLoad32(x2);
			uint32_t w3 = serpentLoad32(x3);
			

			serpent_round(&w0, &w1, &w2, &w3, 0, this);
			serpent_round(&w0, &w1, &w2, &w3, 1, this);
			serpent_round(&w0, &w1, &w2, &w3, 2, this);
			serpent_round(&w0, &w1, &w2, &w3, 3, this);
			serpent_round(&w0, &w1, &w2, &w3, 4, this);
			serpent_round(&w0, &w1, &w2, &w3, 5, this);
			serpent_round(&w0, &w1, &w2, &w3, 6, this);
			serpent_round(&w0, &w1, &w2, &w3, 7, this);
			serpent_round(&w0, &w1, &w2, &w3, 8, this);
			serpent_round(&w0, &w1, &w2, &w3, 9, this);
			serpent_round(&w0, &w1, &w2, &w3, 10, this);
			serpent_round(&w0, &w1, &w2, &w3, 11, this);
			serpent_round(&w0, &w1, &w2, &w3, 12, this);
			serpent_round(&w0, &w1, &w2, &w3, 13, this);
			serpent_round(&w0, &w1, &w2, &w3, 14, this);
			serpent_round(&w0, &w1, &w2, &w3, 15, this);
			serpent_round(&w0, &w1, &w2, &w3, 16, this);
			serpent_round(&w0, &w1, &w2, &w3, 17, this);
			serpent_round(&w0, &w1, &w2, &w3, 18, this);
			serpent_round(&w0, &w1, &w2, &w3, 19, this);
			serpent_round(&w0, &w1, &w2, &w3, 20, this);
			serpent_round(&w0, &w1, &w2, &w3, 21, this);
			serpent_round(&w0, &w1, &w2, &w3, 22, this);
			serpent_round(&w0, &w1, &w2, &w3, 23, this);
			serpent_round(&w0, &w1, &w2, &w3, 24, this);
			serpent_round(&w0, &w1, &w2, &w3, 25, this);
			serpent_round(&w0, &w1, &w2, &w3, 26, this);
			serpent_round(&w0, &w1, &w2, &w3, 27, this);
			serpent_round(&w0, &w1, &w2, &w3, 28, this);
			serpent_round(&w0, &w1, &w2, &w3, 29, this);
			serpent_round(&w0, &w1, &w2, &w3, 30, this);
			
			w0 ^= Subkeys[31<<2];
      w1 ^= Subkeys[(31<<2)+1];
      w2 ^= Subkeys[(31<<2)+2];
      w3 ^= Subkeys[(31<<2)+3];
      applySBox(&w0, &w1, &w2, &w3, 7); /* the last round used S7 */
      w0 ^= Subkeys[32<<2];
      w1 ^= Subkeys[(32<<2)+1];
      w2 ^= Subkeys[(32<<2)+2];
      w3 ^= Subkeys[(32<<2)+3];
      
      serpentStore32(x0, w0);

      serpentStore32(x1, w1);

      serpentStore32(x2, w2);

      serpentStore32(x3, w3);
	}

	void Serpent::decrypt_block(uint8_t *x0,uint8_t *x1,uint8_t *x2,uint8_t *x3) const
	{
			uint32_t w0 = serpentLoad32(x0);
			uint32_t w1 = serpentLoad32(x1);
			uint32_t w2 = serpentLoad32(x2);
			uint32_t w3 = serpentLoad32(x3);

			w0 ^= Subkeys[32<<2];
			w1 ^= Subkeys[(32<<2)+1];
			w2 ^= Subkeys[(32<<2)+2];
			w3 ^= Subkeys[(32<<2)+3];
			applyInvSBox(&w0, &w1, &w2, &w3, 7); /* the last round used S7 */
			w0 ^= Subkeys[31<<2];
			w1 ^= Subkeys[(31<<2)+1];
			w2 ^= Subkeys[(31<<2)+2];
			w3 ^= Subkeys[(31<<2)+3];

			for (int i = 30; i >= 0; --i)
			{
				serpent_invRound(&w0, &w1, &w2, &w3, i, this);
			}

      serpentStore32(x0, w0);

      serpentStore32(x1, w1);

      serpentStore32(x2, w2);

      serpentStore32(x3, w3);
	}

	size_t Serpent::blockSize() const noexcept
	{
		return 16;
	}

	void Serpent::encryptBlock(uint8_t *block) const
	{
		requireKey();
		encrypt_block(block, block + 4, block + 8, block + 12);
	}

	void Serpent::decryptBlock(uint8_t *block) const
	{
		requireKey();
		decrypt_block(block, block + 4, block + 8, block + 12);
	}

	std::vector<uint8_t> Serpent::encrypt(std::span<const uint8_t> plt) const
	{
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

	std::vector<uint8_t> Serpent::decrypt(std::span<const uint8_t> plt) const
	{
		return decryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

} // namespace block
