#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>

#include "Twofish.h"






#define byte0(x) (uint8_t)(x>>24)
#define byte1(x) (uint8_t)(x>>16)
#define byte2(x) (uint8_t)(x>>8)
#define byte3(x) (uint8_t)x


#define PHT(ax, bx) aph = ax; ax =(ax+bx); bx=(aph+(bx<<1));

#define rotl4(xr) (((xr>>1)|(xr<< 3))&0xf)

#define rotr(xr,times) (((xr << times)|(xr >> 32-times)))

#define rotl(xr,times) (((xr >> times)|(xr << 32-times)))



#define MDSmult(hword) hword = ((byte3(temp)^MDSEF[byte2(temp)]^MDS5B[byte1(temp)]^MDS5B[byte0(temp)]))|\
		  		  	 			 ((uint32_t)(MDS5B[byte3(temp)]^MDSEF[byte2(temp)]^MDSEF[byte1(temp)]^byte0(temp))<<8)|\
		  		  				 ((uint32_t)(MDSEF[byte3(temp)]^MDS5B[byte2(temp)]^byte1(temp)^MDSEF[byte0(temp)])<<16)|\
		  		  				 ((uint32_t)(MDSEF[byte3(temp)]^byte2(temp)^MDSEF[byte1(temp)]^MDS5B[byte0(temp)])<<24);

#define h128(hword, hkey)  temp = ( q1[q0[q0[byte0(hword)]^*(hkey)]^*(hkey+4)])|\
						    		((uint32_t)(q0[q0[q1[byte1(hword)]^*(hkey+1)]^*(hkey+5)])<<8)|\
						    		((uint32_t)(q1[q1[q0[byte2(hword)]^*(hkey+2)]^*(hkey+6)])<<16)|\
						    		((uint32_t)(q0[q1[q1[byte3(hword)]^*(hkey+3)]^*(hkey+7)])<<24);\
						    		MDSmult(hword)


#define h196(hword, hkey) temp =  ( q1[q0[q0[q1[byte0(hword)]^*(hkey)]^*(hkey+4)]^*(hkey+8)])|\
						    		((uint32_t)(q0[q0[q1[q1[byte1(hword)]^*(hkey+1)]^*(hkey+5)]^*(hkey+9)])<<8)|\
						    		((uint32_t)(q1[q1[q0[q0[byte2(hword)]^*(hkey+2)]^*(hkey+6)]^*(hkey+10)])<<16)|\
						    		((uint32_t)(q0[q1[q1[q0[byte3(hword)]^*(hkey+3)]^*(hkey+7)]^*(hkey+11)])<<24);\
						    		MDSmult(hword)


#define h256(hword, hkey) temp =  ( q1[q0[q0[q1[q1[byte0(hword)]^*(hkey)]^*(hkey+4)]^*(hkey+8)]^*(hkey+12)])|\
						    		((uint32_t)(q0[q0[q1[q1[q0[byte1(hword)]^*(hkey+1)]^*(hkey+5)]^*(hkey+9)]^*(hkey+13)])<<8)|\
						    		((uint32_t)(q1[q1[q0[q0[q0[byte2(hword)]^*(hkey+2)]^*(hkey+6)]^*(hkey+10)]^*(hkey+14)])<<16)|\
						    		((uint32_t)(q0[q1[q1[q0[q1[byte3(hword)]^*(hkey+3)]^*(hkey+7)]^*(hkey+11)]^*(hkey+15)])<<24);\
						    		MDSmult(hword)


#define g(hword) hword = Sbox0[byte0(hword)]^ Sbox1[byte1(hword)]^Sbox2[byte2(hword)]^ Sbox3[byte3(hword)];
						     

#define round(i, l0,l1,r0,r1, nl0,nl1) nl0 = l0; nl1 = rotr(l1,8);\
						    			  g(nl0)\
						      			  g(nl1)\
						      			  PHT(nl0,nl1)\
						      			  nl0 += Subkeys[2*i+8];\
						      			  nl1 += Subkeys[2*i+9];\
						      			  nl0 = rotl((nl0^r0),1);\
						      			  nl1 ^= rotr(r1,1);

#define invround(i, l0,l1,r0,r1, nl0,nl1) nl0 = l0; nl1 = rotr(l1,8);\
						    			  g(nl0)\
						      			  g(nl1)\
						      			  PHT(nl0,nl1)\
						      			  nl0 += Subkeys[2*i+8];\
						      			  nl1 += Subkeys[2*i+9];\
						      			  nl0 ^= rotr(r0,1);\
						      			  nl1 = rotl((nl1^r1),1);



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
		if (key.size() != 16 && key.size() != 24 && key.size() != 32)
			throw std::invalid_argument("Twofish key must be 16, 24 or 32 bytes");

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
		uint32_t a0, b0, a1, b1, temp, aph;
		Subkeys.clear();
		for (int i = 0 ; i < 20; ++i){
			a0 = 2*i*rho;
			b0 = (2*i+1)*rho;
			switch (n/8){
				case 4:
					h256(a0,&M_even[0]);
					h256(b0,&M_odd[0]);
					break;
				case 3:
					h196(a0,&M_even[0]);
					h196(b0,&M_odd[0]);
					break;
				case 2:
					h128(a0,&M_even[0]);
					h128(b0,&M_odd[0]);
					break;
			}
			b0 = rotr(b0,8);
			PHT(a0,b0)	
			Subkeys.push_back(a0);
			b0 = rotr(b0,9);
			Subkeys.push_back(b0);	 
		}
	}

	void Twofish::encrypt_block(uint8_t *lb0,uint8_t *lb1,uint8_t *rb0,uint8_t *rb1) const
	{
		uint32_t left0, left1, right0, right1,newl0, newl1, temp, aph;
		
		left0 = (*lb0)| ((uint32_t)*(lb0+1)<<8)|((uint32_t)*(lb0+2)<<16)| ((uint32_t)*(lb0+3)<<24);
		left1 = (*lb1)| ((uint32_t)*(lb1+1)<<8)|((uint32_t)*(lb1+2)<<16)| ((uint32_t)*(lb1+3)<<24);
		right0 = (*rb0)| ((uint32_t)*(rb0+1)<<8)|((uint32_t)*(rb0+2)<<16)| ((uint32_t)*(rb0+3)<<24);
		right1 = (*rb1)| ((uint32_t)*(rb1+1)<<8)|((uint32_t)*(rb1+2)<<16)| ((uint32_t)*(rb1+3)<<24);
		

		left0 ^= Subkeys[0]; left1 ^= Subkeys[1];
		right0 ^= Subkeys[2]; right1 ^= Subkeys[3];

		round( 0, left0, left1, right0, right1, newl0, newl1)
		round( 1, newl0, newl1, left0, left1, right0, right1)
		round( 2, right0, right1, newl0, newl1, left0, left1)
		round( 3, left0, left1, right0, right1, newl0, newl1)
		round( 4, newl0, newl1, left0, left1, right0, right1)
		round( 5, right0, right1, newl0, newl1, left0, left1)
		round( 6, left0, left1, right0, right1, newl0, newl1)
		round( 7, newl0, newl1, left0, left1, right0, right1)
		round( 8, right0, right1, newl0, newl1, left0, left1)
		round( 9, left0, left1, right0, right1, newl0, newl1)
		round(10, newl0, newl1, left0, left1, right0, right1)
		round(11, right0, right1, newl0, newl1, left0, left1)
		round(12, left0, left1, right0, right1, newl0, newl1)
		round(13, newl0, newl1, left0, left1, right0, right1)
		round(14, right0, right1, newl0, newl1, left0, left1)
		round(15, left0, left1, right0, right1, newl0, newl1)

		left0 ^= Subkeys[4]; left1 ^= Subkeys[5];
		newl0 ^= Subkeys[6]; newl1 ^= Subkeys[7];
		
		*lb0 = byte3(left0); *(lb0+1) = byte2(left0);*(lb0+2) = byte1(left0); *(lb0+3) = byte0(left0);
		*lb1 = byte3(left1); *(lb1+1) = byte2(left1);*(lb1+2) = byte1(left1); *(lb1+3) = byte0(left1);
		*rb0 = byte3(newl0); *(rb0+1) = byte2(newl0);*(rb0+2) = byte1(newl0); *(rb0+3) = byte0(newl0);
		*rb1 = byte3(newl1); *(rb1+1) = byte2(newl1);*(rb1+2) = byte1(newl1); *(rb1+3) = byte0(newl1);
	}

	void Twofish::decrypt_block(uint8_t *lb0,uint8_t *lb1,uint8_t *rb0,uint8_t *rb1) const
	{
		uint32_t left0, left1, right0, right1,newl0, newl1, temp, aph;
		
left0 = (*lb0)| ((uint32_t)*(lb0+1)<<8)|((uint32_t)*(lb0+2)<<16)| ((uint32_t)*(lb0+3)<<24);
		left1 = (*lb1)| ((uint32_t)*(lb1+1)<<8)|((uint32_t)*(lb1+2)<<16)| ((uint32_t)*(lb1+3)<<24);
		right0 = (*rb0)| ((uint32_t)*(rb0+1)<<8)|((uint32_t)*(rb0+2)<<16)| ((uint32_t)*(rb0+3)<<24);
		right1 = (*rb1)| ((uint32_t)*(rb1+1)<<8)|((uint32_t)*(rb1+2)<<16)| ((uint32_t)*(rb1+3)<<24);
		

		left0 ^= Subkeys[4]; left1 ^= Subkeys[5];
		right0 ^= Subkeys[6]; right1 ^= Subkeys[7];
		
		invround(15, left0, left1, right0, right1, newl0, newl1)
		invround(14, newl0, newl1, left0, left1, right0, right1)
		invround(13, right0, right1, newl0, newl1, left0, left1)
		invround(12, left0, left1, right0, right1, newl0, newl1)
		invround(11, newl0, newl1, left0, left1, right0, right1)
		invround(10, right0, right1, newl0, newl1, left0, left1)
		invround( 9, left0, left1, right0, right1, newl0, newl1)
		invround( 8, newl0, newl1, left0, left1, right0, right1)
		invround( 7, right0, right1, newl0, newl1, left0, left1)
		invround( 6, left0, left1, right0, right1, newl0, newl1)
		invround( 5, newl0, newl1, left0, left1, right0, right1)
		invround( 4, right0, right1, newl0, newl1, left0, left1)
		invround( 3, left0, left1, right0, right1, newl0, newl1)
		invround( 2, newl0, newl1, left0, left1, right0, right1)
		invround( 1, right0, right1, newl0, newl1, left0, left1)
		invround( 0, left0, left1, right0, right1, newl0, newl1)

		left0 ^= Subkeys[0]; left1 ^= Subkeys[1];
		newl0 ^= Subkeys[2]; newl1 ^= Subkeys[3];
		
		*lb0 = byte3(left0); *(lb0+1) = byte2(left0);*(lb0+2) = byte1(left0); *(lb0+3) = byte0(left0);
		*lb1 = byte3(left1); *(lb1+1) = byte2(left1);*(lb1+2) = byte1(left1); *(lb1+3) = byte0(left1);
		*rb0 = byte3(newl0); *(rb0+1) = byte2(newl0);*(rb0+2) = byte1(newl0); *(rb0+3) = byte0(newl0);
		*rb1 = byte3(newl1); *(rb1+1) = byte2(newl1);*(rb1+2) = byte1(newl1); *(rb1+3) = byte0(newl1);
	}

	

	
	int Twofish::blockSize() const
	{
		return 16;
	}

	void Twofish::encryptBlock(uint8_t *block) const
	{
		encrypt_block(block, block + 4, block + 8, block + 12);
	}

	void Twofish::decryptBlock(uint8_t *block) const
	{
		decrypt_block(block, block + 4, block + 8, block + 12);
	}

	std::vector<uint8_t> Twofish::encrypt(std::vector<uint8_t> plt, std::vector<uint8_t> iv) const
	{
		return encryptMode(plt, BlockMode::CBC, Padding::PKCS7, iv);
	}

	static Padding twofishPadding(int p)
	{
		switch (p)
		{
			case 0: return Padding::Zeros;
			case 2: return Padding::ANSIX923;
			case 3: return Padding::ISO78164;
			default: return Padding::PKCS7;
		}
	}

	void Twofish::encrypt_File(char* path) const
	{
		uint8_t ts[16] = {(uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff};
		std::ifstream input_file(path, std::ios::binary);
		std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
		input_file.close();
		int l = vec.size();
		int m = l%16 != 0 ? (l/16+1)*16-l: 0;
		if(m)
			pad(vec, m, twofishPadding(padding));
		if(!vec.empty())
		{
			switch(mode)
			{
				case 0: encryptECB(&vec[0], vec.size()); break;
				case 1: encryptCBC(&vec[0], vec.size(), &ts[0]); break;
			}
		}
		std::ofstream file(path);
		if(!vec.empty())
			file.write(reinterpret_cast<char*>(&vec[0]), vec.size() * sizeof(vec[0]));
    	file.close();
	}

	void Twofish::encrypt_FileS(std::string path) const
	{
		uint8_t ts[16] = {(uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff};
		std::ifstream input_file(path, std::ios::binary);
		std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
		input_file.close();
		int l = vec.size();
		int m = l%16 != 0 ? (l/16+1)*16-l: 0;
		if(m)
			pad(vec, m, twofishPadding(padding));
		if(!vec.empty())
		{
			switch(mode)
			{
				case 0: encryptECB(&vec[0], vec.size()); break;
				case 1: encryptCBC(&vec[0], vec.size(), &ts[0]); break;
			}
		}
		std::ofstream file(path);
		if(!vec.empty())
			file.write(reinterpret_cast<char*>(&vec[0]), vec.size() * sizeof(vec[0]));
    	file.close();
	}

	void Twofish::decrypt_File(char* path) const
	{	
		uint8_t ts[16] = {(uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff, (uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff,(uint8_t)0xff};

		std::ifstream input_file(path, std::ios::binary);
		std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
		input_file.close();
		if(!vec.empty())
		{
			switch(mode)
			{
				case 0: decryptECB(&vec[0], vec.size()); 
						break;
				case 1: decryptCBC(&vec[0], vec.size(), &ts[0]);
						break;
			}
		}
		
		std::ofstream file(path);
		if(!vec.empty())
			file.write(reinterpret_cast<char*>(&vec[0]), vec.size() * sizeof(vec[0]));
    	file.close();
	}


