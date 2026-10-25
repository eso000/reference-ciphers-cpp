#include <vector>
#include <string>
#include <stdexcept>

#include "TestBase.h"
#include "vectors.h"
#include "block/AES.h"

using namespace block;

class AESSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<AES> c(new AES());
		c->generateKeys(hexToVec(keyHex));
		return c;
	}
};

int main()
{
	/* The FIPS keys double as the round-trip and vector-API keys below. */
	const char *K128 = AES_FIPS[0].key;
	const char *K192 = AES_FIPS[1].key;
	const char *K256 = AES_FIPS[2].key;

	AESSuite suite;

	printf("== FIPS-197 single block / NIST SP 800-38A ECB ==\n");
	suite.runEcbKats(asKats(AES_FIPS));
	suite.runEcbKatsDec(asKats(AES_FIPS));
	suite.runEcbKats(asKats(AES_SP800_ECB));
	suite.runEcbKatsDec(asKats(AES_SP800_ECB));

	printf("== vector API / PKCS#7 padding ==\n");
	try
	{
		AES c, d;
		c.generateKeys(hexToVec(K256));
		d.generateKeys(hexToVec(K256));
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
		c.generateKeys(hexToVec(K256));
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

	/* AES accepts a 128, 192 or 256-bit key, i.e. 16, 24 or 32 bytes. An
	   earlier version rounded the length up to the next of those sizes and
	   padded with '0', so a 16.5-byte key silently became a valid AES-192 key
	   holding a byte the caller never wrote, and anything longer than 32 bytes
	   was truncated. Both are refused. */
	printf("== key length validation ==\n");
	{
		const size_t accepted[] = {16, 24, 32};
		for (size_t n : accepted)
		{
			bool threw = false;
			try { AES c; c.generateKeys(std::vector<uint8_t>(n, 0)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu byte key accepted (AES-%d)", n, (int)n * 8);
			CHECK(!threw, name);
		}

		const size_t rejected[] = {0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48, 64};
		for (size_t n : rejected)
		{
			bool threw = false;
			try { AES c; c.generateKeys(std::vector<uint8_t>(n, 0)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu byte key rejected", n);
			CHECK(threw, name);
		}
	}

	printf("== vector API padding edge cases ==\n");
	try
	{
		AES c, d;
		c.generateKeys(hexToVec(K256));
		d.generateKeys(hexToVec(K256));
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
		c.generateKeys(hexToVec(K128));
		d.generateKeys(hexToVec(K128));
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
		c.generateKeys(hexToVec(K128));
		d.generateKeys(hexToVec(K128));
		std::vector<uint8_t> pt = hexToVec("00112233445566778899aabbccddeeff");
		std::vector<uint8_t> ct = c.encrypt(pt);
		ct[31] = 0x00;
		d.decrypt(ct);
		CHECK(0, "invalid padding is rejected");
	}
	catch (const std::invalid_argument &)
	{
		CHECK(1, "invalid padding is rejected");
	}
	catch (...)
	{
		CHECK(0, "vector API invalid padding");
	}

	return suite.report();
}
