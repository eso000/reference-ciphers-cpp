#include <vector>
#include <string>
#include <fstream>

#include "Serpent.h"
#include <iterator>
#include "Serpent_data.h"

Serpent::Serpent()
{
	SBox.clear();
	for (const auto& r : SBox_data) SBox.emplace_back(std::begin(r), std::end(r));
	invSBox.clear();
	for (const auto& r : invSBox_data) invSBox.emplace_back(std::begin(r), std::end(r));
}


#define rotr(xr,times) (((xr << times)|(xr >> 32-times)))

#define rotl(xr,times) (((xr >> times)|(xr << 32-times)))

#define LT(x0, x1, x2, x3){\
        x0 = rotl(x0, 13);\
        x2 = rotl(x2, 3);\
        x1 = x1^x0^x2;\
        x3 = x3^x2^(x0>>3);\
        x1 = rotl(x1, 1);\
        x3 = rotl(x3, 7);\
        x0 = x0^x1^x3;\
        x2 = x2^x3^ (x1>>7);\
        x0 = rotl(x0, 5);\
        x2 = rotl(x2, 22);}


#define invLT(x0, x1, x2, x3){\
        x2 = rotr(x2, 22);\
        x0 = rotr(x0, 5);\
        x2 = x2^x3^(x1>>7);\
        x0 = x0^x1^x3;\
        x3 = rotr(x3, 7);\
        x1 = rotr(x1, 1);\
        x3 = x3^x2^(x0>>3);\
        x1 = x1^x0^x2;\
        x2 = rotr(x2, 3);\
        x0 = rotr(x0, 13);}

#define SboxstepInv(x) newbits = invSBox[n][(((*x0>>x)&1) <<0 |\
                                         								 ((*x1>>x)&1) <<1 |\
                                         								 ((*x2>>x)&1) <<2 |\
                                         								 ((*x3>>x)&1) <<3 )];\
            nx0 |= ((newbits >> 0)&1) << x;\
            nx1 |= ((newbits >> 1)&1) << x;\
            nx2 |= ((newbits >> 2)&1) << x;\
            nx3 |= ((newbits >> 3)&1) << x;

#define round(i, p0,p1,p2,p3) p0 ^= Subkeys[(i<<2)];\
        											p1 ^= Subkeys[(i<<2)+1];\
        											p2 ^= Subkeys[(i<<2)+2];\
        											p3 ^= Subkeys[(i<<2)+3];\
        											applySBox(&p0, &p1, &p2, &p3, i%8);\
        											LT(p0, p1, p2, p3)

#define roundInv(i, p0,p1,p2,p3) invLT(p0, p1, p2, p3);\
        											applyInvSBox(&p0, &p1, &p2, &p3, i%8);\
        											p0 ^= Subkeys[(i<<2)];\
        											p1 ^= Subkeys[(i<<2)+1];\
        											p2 ^= Subkeys[(i<<2)+2];\
        											p3 ^= Subkeys[(i<<2)+3];


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
		bin += '0';
		std::string out;
		for (int i = 0; i < 256; i += 4)
		{
			int v = ((bin[i]-'0')<<3)|((bin[i+1]-'0')<<2)|((bin[i+2]-'0')<<1)|(bin[i+3]-'0');
			out += "0123456789abcdef"[v];
		}
		return out;
	}


	uint8_t Serpent::ltb(uint8_t v) const
	{
		uint8_t result = 0; 
		for (int i = 0; i < 8; ++i)
		{
			result += (v>>i)&1;
			if (i != 7)
				result <<= 1;
		}
		return result;
	}

	uint32_t Serpent::ltb( std::string s) const
	{
		uint32_t result = 0;
		for (int i = 0; i < 8; i=i+2)
		 {	
		 	 result += ltb(std::stoul(s.substr(i,2), 0, 16));
		 	 if(i != 6)
		 	 	result <<= 8;
		 } 
		return result;
	}

	uint32_t Serpent::ltb32( int v) const
	{
		uint32_t result = 0; 
		for (int i = 0; i < 32; ++i)
		{
			result += (v>>i)&1;
			if (i != 31)
				result <<= 1;
		}
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
        uint8_t newbits = 0;

        for (int x = 0; x < 32; ++x)
        {
            SboxstepInv(x)
        }

        *x0 = nx0;
        *x1 = nx1;
        *x2 = nx2;
        *x3 = nx3;
    }

	void Serpent::generateKeys(std::string key)
	{
    key = padKeyBit(key);
    uint32_t wi;
    uint32_t w[140];

    for (int i = 0; i<64; i = i + 8)
    {
      w[i/8] = ltb(key.substr(i,8));
    }

       
    for(int i=8; i< 140;++i){
      wi = w[i - 8]^ w[i - 5]^ w[i - 3]^ w[i - 1]^2644438137L^ltb32(i-8);
      wi = rotl(wi,11);
      w[i] = wi;
     }
     for (int i=0;i<33;++i)
     {
            applySBox(&w[4*i+8],&w[4*i+1+8],&w[4*i+2+8],&w[4*i+3+8],(((32 + 3 - i) % 32)%8));
     }        
        Subkeys.clear();
        for (uint32_t *i = &w[0]+8; i < &w[0]+140; ++i)
        {
        	Subkeys.push_back(*i);
        }

    }

	void Serpent::encrypt_block(uint8_t *x0,uint8_t *x1,uint8_t *x2,uint8_t *x3) const
	{
			uint32_t w0 = (ltb(*x0)<<24) + (ltb(*(x0+1))<<16) + (ltb(*(x0+2))<<8) + ltb(*(x0+3));
			uint32_t w1 = (ltb(*x1)<<24) + (ltb(*(x1+1))<<16) + (ltb(*(x1+2))<<8) + ltb(*(x1+3));
			uint32_t w2 = (ltb(*x2)<<24) + (ltb(*(x2+1))<<16) + (ltb(*(x2+2))<<8) + ltb(*(x2+3));
			uint32_t w3 = (ltb(*x3)<<24) + (ltb(*(x3+1))<<16) + (ltb(*(x3+2))<<8) + ltb(*(x3+3));
			

			round( 0,w0,w1,w2,w3)
			round( 1,w0,w1,w2,w3)
			round( 2,w0,w1,w2,w3)
			round( 3,w0,w1,w2,w3)
			round( 4,w0,w1,w2,w3)
			round( 5,w0,w1,w2,w3)
			round( 6,w0,w1,w2,w3)
			round( 7,w0,w1,w2,w3)
			round( 8,w0,w1,w2,w3)
			round( 9,w0,w1,w2,w3)
			round(10,w0,w1,w2,w3)
			round(11,w0,w1,w2,w3)
			round(12,w0,w1,w2,w3)
			round(13,w0,w1,w2,w3)
			round(14,w0,w1,w2,w3)
			round(15,w0,w1,w2,w3)
			round(16,w0,w1,w2,w3)
			round(17,w0,w1,w2,w3)
			round(18,w0,w1,w2,w3)
			round(19,w0,w1,w2,w3)
			round(20,w0,w1,w2,w3)
			round(21,w0,w1,w2,w3)
			round(22,w0,w1,w2,w3)
			round(23,w0,w1,w2,w3)
			round(24,w0,w1,w2,w3)
			round(25,w0,w1,w2,w3)
			round(26,w0,w1,w2,w3)
			round(27,w0,w1,w2,w3)
			round(28,w0,w1,w2,w3)
			round(29,w0,w1,w2,w3)
			round(30,w0,w1,w2,w3)
			
			w0 ^= Subkeys[31<<2];
      w1 ^= Subkeys[(31<<2)+1];
      w2 ^= Subkeys[(31<<2)+2];
      w3 ^= Subkeys[(31<<2)+3];
      applySBox(&w0, &w1, &w2, &w3, 31%8);
      w0 ^= Subkeys[32<<2];
      w1 ^= Subkeys[(32<<2)+1];
      w2 ^= Subkeys[(32<<2)+2];
      w3 ^= Subkeys[(32<<2)+3];
      
      *x0 = ltb(w0>>24 & 0xff); *(x0+1) = ltb((w0>>16 ) & 0xff); 
      *(x0+2) = ltb((w0>>8 ) & 0xff); *(x0+3) = ltb(w0 & 0xff);

      *x1 = ltb(w1>>24 & 0xff); *(x1+1) = ltb((w1>>16 ) & 0xff); 
      *(x1+2) = ltb((w1>>8 ) & 0xff); *(x1+3) = ltb(w1 & 0xff);

			*x2 = ltb(w2>>24 & 0xff); *(x2+1) = ltb((w2>>16 ) & 0xff); 
      *(x2+2) = ltb((w2>>8 ) & 0xff); *(x2+3) = ltb(w2 & 0xff);

      *x3 = ltb(w3>>24 & 0xff); *(x3+1) = ltb((w3>>16 ) & 0xff); 
      *(x3+2) = ltb((w3>>8 ) & 0xff); *(x3+3) = ltb(w3 & 0xff);
	}

	void Serpent::decrypt_block(uint8_t *x0,uint8_t *x1,uint8_t *x2,uint8_t *x3) const
	{
			uint32_t w0 = (ltb(*x0)<<24) + (ltb(*(x0+1))<<16) + (ltb(*(x0+2))<<8) + ltb(*(x0+3));
			uint32_t w1 = (ltb(*x1)<<24) + (ltb(*(x1+1))<<16) + (ltb(*(x1+2))<<8) + ltb(*(x1+3));
			uint32_t w2 = (ltb(*x2)<<24) + (ltb(*(x2+1))<<16) + (ltb(*(x2+2))<<8) + ltb(*(x2+3));
			uint32_t w3 = (ltb(*x3)<<24) + (ltb(*(x3+1))<<16) + (ltb(*(x3+2))<<8) + ltb(*(x3+3));

			w0 ^= Subkeys[32<<2];
			w1 ^= Subkeys[(32<<2)+1];
			w2 ^= Subkeys[(32<<2)+2];
			w3 ^= Subkeys[(32<<2)+3];
			applyInvSBox(&w0, &w1, &w2, &w3, 31%8);
			w0 ^= Subkeys[31<<2];
			w1 ^= Subkeys[(31<<2)+1];
			w2 ^= Subkeys[(31<<2)+2];
			w3 ^= Subkeys[(31<<2)+3];

			for (int i = 30; i >= 0; --i)
			{
				roundInv(i, w0,w1,w2,w3)
			}

      *x0 = ltb(w0>>24 & 0xff); *(x0+1) = ltb((w0>>16 ) & 0xff); 
      *(x0+2) = ltb((w0>>8 ) & 0xff); *(x0+3) = ltb(w0 & 0xff);

      *x1 = ltb(w1>>24 & 0xff); *(x1+1) = ltb((w1>>16 ) & 0xff); 
      *(x1+2) = ltb((w1>>8 ) & 0xff); *(x1+3) = ltb(w1 & 0xff);

			*x2 = ltb(w2>>24 & 0xff); *(x2+1) = ltb((w2>>16 ) & 0xff); 
      *(x2+2) = ltb((w2>>8 ) & 0xff); *(x2+3) = ltb(w2 & 0xff);

      *x3 = ltb(w3>>24 & 0xff); *(x3+1) = ltb((w3>>16 ) & 0xff); 
      *(x3+2) = ltb((w3>>8 ) & 0xff); *(x3+3) = ltb(w3 & 0xff);
	}

	int Serpent::blockSize() const
	{
		return 16;
	}

	void Serpent::encryptBlock(uint8_t *block) const
	{
		encrypt_block(block, block + 4, block + 8, block + 12);
	}

	void Serpent::decryptBlock(uint8_t *block) const
	{
		decrypt_block(block, block + 4, block + 8, block + 12);
	}

	std::vector<uint8_t> Serpent::encrypt(std::vector<uint8_t> plt) const
	{
		return encryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}

	std::vector<uint8_t> Serpent::decrypt(std::vector<uint8_t> plt) const
	{
		return decryptMode(plt, BlockMode::ECB, Padding::PKCS7);
	}
