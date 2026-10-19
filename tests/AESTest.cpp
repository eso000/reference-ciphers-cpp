#include <vector>
#include <string>
#include <stdexcept>

#include "TestBase.h"
#include "block/AES.h"

class AESSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<AES> c(new AES());
		c->generateKeys(keyHex);
		return c;
	}
};

int main()
{
	const char *K128 = "000102030405060708090a0b0c0d0e0f";
	const char *K192 = "000102030405060708090a0b0c0d0e0f1011121314151617";
	const char *K256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	const char *P0 = "00112233445566778899aabbccddeeff";

	const char *S128 = "2b7e151628aed2a6abf7158809cf4f3c";
	const char *S192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
	const char *S256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
	const char *SP = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	const char *SC128 = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4";
	const char *SC192 = "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e";
	const char *SC256 = "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7";

	const std::vector<BlockKat> kats = {
		{"fips-197 C.1 AES-128", K128, P0, "69c4e0d86a7b0430d8cdb78070b4c55a"},
		{"fips-197 C.2 AES-192", K192, P0, "dda97ca4864cdfe06eaf70a0ec0d7191"},
		{"fips-197 C.3 AES-256", K256, P0, "8ea2b7ca516745bfeafc49904b496089"},
		{"sp800-38a ecb AES-128", S128, SP, SC128},
		{"sp800-38a ecb AES-192", S192, SP, SC192},
		{"sp800-38a ecb AES-256", S256, SP, SC256},
	};

	AESSuite suite;

	printf("== FIPS-197 single block / NIST SP 800-38A ECB ==\n");
	suite.runEcbKats(kats);
	suite.runEcbKatsDec(kats);

	printf("== vector API / PKCS#7 padding ==\n");
	try
	{
		AES c, d;
		c.generateKeys(K256);
		d.generateKeys(K256);
		std::vector<uint8_t> pt = hexToVec("00112233445566778899aabbccddeeff00112233445566778899aabbcc");
		std::vector<uint8_t> ct = c.encrypt(pt);
		CHECK(ct.size() == 32, "encrypt(vector) pads 21 bytes to 32");
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(compareVector(rt, pt), "decrypt(vector) strips PKCS#7 padding");
	}
	catch (...)
	{
		CHECK(0, "vector API 21-byte round trip");
	}
	try
	{
		AES c;
		c.generateKeys(K256);
		std::vector<uint8_t> pt = hexToVec("00112233445566778899aabbccddeeff");
		CHECK(c.encrypt(pt).size() == 32, "encrypt(vector) adds full block when aligned");
	}
	catch (...)
	{
		CHECK(0, "vector API full padding block");
	}

	printf("== ECB multi-block round trip ==\n");
	suite.runEcbRoundTrip(K128, 32, "AES-128");
	suite.runEcbRoundTrip(K192, 32, "AES-192");
	suite.runEcbRoundTrip(K256, 32, "AES-256");

	/* AES accepts a 128, 192 or 256-bit key, i.e. 32, 48 or 64 hex
	   characters. generateKeys used to round the length up to the next of
	   those sizes and pad with '0', so a 33-character key silently became a
	   valid AES-192 key holding a '0' the caller never wrote, and anything
	   past 64 characters was truncated. Both are refused now. */
	printf("== key length validation ==\n");
	{
		const size_t accepted[] = {32, 48, 64};
		for (size_t n : accepted)
		{
			bool threw = false;
			try { AES c; c.generateKeys(std::string(n, '0')); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu character key accepted (AES-%d)", n, (int)(n / 2) * 8);
			CHECK(!threw, name);
		}

		const size_t rejected[] = {0, 1, 16, 30, 31, 33, 40, 47, 49, 63, 65, 128};
		for (size_t n : rejected)
		{
			bool threw = false;
			try { AES c; c.generateKeys(std::string(n, '0')); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu character key rejected", n);
			CHECK(threw, name);
		}

		/* The three lengths that used to be padded up, named individually
		   because that silent coercion is the actual regression. */
		const size_t padded[] = {1, 33, 49};
		for (size_t n : padded)
		{
			bool threw = false;
			try { AES c; c.generateKeys(std::string(n, '0')); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu character key no longer zero-padded to a valid size", n);
			CHECK(threw, name);
		}
	}

	printf("== vector API padding edge cases ==\n");
	try
	{
		AES c, d;
		c.generateKeys(K256);
		d.generateKeys(K256);
		std::vector<uint8_t> pt;
		std::vector<uint8_t> ct = c.encrypt(pt);
		CHECK(ct.size() == 16, "empty input padded to one full block");
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(compareVector(rt, pt), "empty input round trip");
	}
	catch (...)
	{
		CHECK(0, "vector API empty input");
	}
	try
	{
		AES c, d;
		c.generateKeys(K128);
		d.generateKeys(K128);
		std::vector<uint8_t> pt(31, 0x42);
		std::vector<uint8_t> ct = c.encrypt(pt);
		CHECK(ct.size() == 32, "31-byte input padded to two blocks");
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(compareVector(rt, pt), "31-byte input round trip");
	}
	catch (...)
	{
		CHECK(0, "vector API 31-byte round trip");
	}
	try
	{
		AES c, d;
		c.generateKeys(K128);
		d.generateKeys(K128);
		std::vector<uint8_t> pt = hexToVec("00112233445566778899aabbccddeeff");
		std::vector<uint8_t> ct = c.encrypt(pt);
		ct[31] = 0x00;
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(rt.size() == 32, "invalid padding is not stripped");
	}
	catch (...)
	{
		CHECK(0, "vector API invalid padding");
	}

	return suite.report();
}
