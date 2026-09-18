#include <vector>
#include <string>
#include <iostream>

#include <fstream>
#include <sstream>

#include <chrono>
#include <thread>


#include "Twofish.h"
#include "Blowfish.h"
#include "AES.h"


void printVec(std::vector<uint8_t> v){
	for (uint8_t* chr = &v[0]; chr< &v[0]+v.size(); ++chr){
        printf("%.2x", *chr);
	printf("\n");
}

uint8_t comprareVector(std::vector<uint8_t> v, std::vector<uint8_t> w)
{
        if (v.size() != w.size())
                return 0;

        for (int i = 0; i < v.size(); ++i)
        {
                if (v[i] != w[i])
                        return 0;
    }   
    return 1;
}




int main(int argc, char const *argv[])
{
	{
		
		Blowfish c = Blowfish();
		c.generateKeys("AABB09182736CCDD");
		//c.generateKeys("74b57f06d9d78c2aec14559a74cf973cec14559a74cf973c");
		
		std::vector<uint8_t> v({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36});
		
		std::vector<uint8_t> testVector({0xc8, 0xfd, 0xca, 0xea, 0x64, 0xfa, 0x2c, 0x82});
		c.encryptECB(&v[0], 8);
		printf("%u\n", comprareVector(v, testVector));	
	}

	{
		AES c = AES();

		c.generateKeys("5468617473206d79204b756e672046755468617473206d79204b756e67204675");
	
		std::string test = "74b57f06d9d78c2aec14559a74cf973c";
		std::vector<uint8_t> v({0x74, 0xb5, 0x7f, 0x06, 0xd9, 0xd7, 0x8c, 0x2a, 0xec, 0x14, 0x55, 0x9a, 0x74, 0xcf, 0x97, 0x3c});
	
		std::vector<uint8_t> testVector({0x14, 0x9d, 0xa0, 0xc3, 0xe6, 0x23, 0x01, 0xb5, 0xc7, 0x25, 0xeb, 0xb8, 0xaa, 0x99, 0x1d, 0x3c});	
		c.encrypt_block256(&v[0]);
 	        printf("%u\n", comprareVector(v, testVector));
	}

	{
		
		Twofish c = Twofish();
		c.generateKeys("5468617473206d79204b756e672046755468617473206d79204b756e67204675");
		//c.generateKeys("74b57f06d9d78c2aec14559a74cf973cec14559a74cf973c");
		
		std::vector<uint8_t> v({0x74, 0xb5, 0x7f, 0x06, 0xd9, 0xd7, 0x8c, 0x2a, 0xec, 0x14, 0x55, 0x9a, 0x74, 0xcf, 0x97, 0x3c});
		c.encryptECB(&v[0],16);
		
		std::vector<uint8_t> testVector({0x21, 0xc5, 0xb0, 0x05, 0xfa, 0x12, 0x7a, 0x86, 0x4c, 0x58, 0x21, 0x7b, 0x2d, 0xd2, 0xb7, 0x03});
		printf("%u\n", comprareVector(v, testVector));
	}
	return 0;
}
