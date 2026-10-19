#include <vector>
#include <string>
#include <stdexcept>

#include "TestBase.h"
#include "block/DES.h"

/* DES ships two implementations of the initial/final permutation (the naive
   table lookup and the delta-swap network), selected by the constructor. The
   published vectors anchor the default path; the other is a second suite so
   both are checked the same way. */
class DESAltSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<DES> c(new DES(true));
		c->generateKeys(keyHex);
		return c;
	}
};

class DESNaiveSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<DES> c(new DES(false));
		c->generateKeys(keyHex);
		return c;
	}
};

int main()
{
	const char *K1 = "133457799BBCDFF1";
	const char *K2 = "0E329232EA6D0D73";
	const char *K3 = "AABB09182736CCDD";

	const char *katKeys[] = {K1, K2, K3};
	const char *katPlain[] = {"0123456789ABCDEF", "8787878787878787", "123456ABCD132536"};
	const char *katCipher[] = {"85E813540F0AB405", "0000000000000000", "C0B7A8D05F3A829C"};

	std::vector<BlockKat> altKats, naiveKats;
	for (int i = 0; i < 3; ++i)
	{
		altKats.push_back(BlockKat{"kat " + std::to_string(i + 1) + " (alt)", katKeys[i], katPlain[i], katCipher[i]});
		naiveKats.push_back(BlockKat{"kat " + std::to_string(i + 1) + " (naive)", katKeys[i], katPlain[i], katCipher[i]});
	}

	printf("== standard DES known-answer tests (both IP/FP implementations) ==\n");
	DESAltSuite alt;
	DESNaiveSuite naive;
	alt.runEcbKats(altKats);
	alt.runEcbKatsDec(altKats);
	naive.runEcbKats(naiveKats);
	naive.runEcbKatsDec(naiveKats);

	printf("== delta-swap networks vs spec tables ==\n");
	{
		DES c;
		uint64_t x = 0x123456789abcdef0ULL;
		int checked = 0;
		for (int i = 0; i < 256; ++i)
		{
			x = x * 6364136223846793005ULL + 1442695040888963407ULL;
			if (DES::ip_perm_alt(x) == c.permutate(x, c.initialperm, 64))
				++checked;
		}
		CHECK(checked == 256, "ip_perm_alt equals IP table (256 random blocks)");
		checked = 0;
		x = 0x123456789abcdef0ULL;
		for (int i = 0; i < 256; ++i)
		{
			x = x * 6364136223846793005ULL + 1442695040888963407ULL;
			if (DES::fp_perm_alt(x) == c.permutate(x, c.inverseperm, 64))
				++checked;
		}
		CHECK(checked == 256, "fp_perm_alt equals FP table (256 random blocks)");
		checked = 0;
		x = 0x123456789abcdef0ULL;
		for (int i = 0; i < 256; ++i)
		{
			x = x * 6364136223846793005ULL + 1442695040888963407ULL;
			if (DES::fp_perm_alt(DES::ip_perm_alt(x)) == x)
				++checked;
		}
		CHECK(checked == 256, "fp_perm_alt(ip_perm_alt(x)) == x (256 random blocks)");
	}

	printf("== alt vs naive agree ==\n");
	{
		DES a(true), b(false);
		a.generateKeys(K3);
		b.generateKeys(K3);
		std::vector<uint8_t> in = hexToVec("123456ABCD132536");
		std::vector<uint8_t> ca = in, cb = in;
		a.encryptECB(&ca[0], 8);
		b.encryptECB(&cb[0], 8);
		CHECK(compareVector(ca, cb), "alt==naive encrypt");
		a.decryptECB(&ca[0], 8);
		b.decryptECB(&cb[0], 8);
		CHECK(compareVector(ca, cb) && compareVector(ca, in), "alt==naive decrypt");
	}

	printf("== ECB multi-block round trip ==\n");
	alt.runEcbRoundTrip(K3, 16, "DES");

	printf("== CBC round trip ==\n");
	{
		DES c, d;
		c.generateKeys(K3);
		d.generateKeys(K3);
		std::vector<uint8_t> v, w, iv, iv2;
		for (int i = 0; i < 16; ++i)
			v.push_back((uint8_t)(0xA0 + i));
		w = v;
		for (int i = 0; i < 8; ++i)
			iv.push_back(0x00);
		iv2 = iv;
		c.encryptCBC(&v[0], (int)v.size(), &iv[0]);
		CHECK(!compareVector(v, w), "cbc ciphertext differs from plaintext");
		d.decryptCBC(&v[0], (int)v.size(), &iv2[0]);
		CHECK(compareVector(v, w), "cbc encrypt+decrypt restores plaintext");
	}

	printf("== vector API / PKCS#7 padding ==\n");
	try
	{
		DES c, d;
		c.generateKeys(K3);
		d.generateKeys(K3);
		std::vector<uint8_t> pt = hexToVec("00112233445566778899AABBCCDDEEFF");
		std::vector<uint8_t> ct = c.encrypt(pt);
		CHECK(ct.size() == 24, "encrypt(vector) pads 16 bytes to 24");
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(compareVector(rt, pt), "decrypt(vector) strips PKCS#7 padding");
	}
	catch (...)
	{
		CHECK(0, "vector API 16-byte round trip");
	}
	try
	{
		DES c;
		c.generateKeys(K3);
		std::vector<uint8_t> pt = hexToVec("ABCD");
		CHECK(c.encrypt(pt).size() == 8, "encrypt(vector) pads 2 bytes to one block");
	}
	catch (...)
	{
		CHECK(0, "vector API short input");
	}
	try
	{
		DES c, d;
		c.generateKeys(K3);
		d.generateKeys(K3);
		std::vector<uint8_t> pt;
		std::vector<uint8_t> ct = c.encrypt(pt);
		CHECK(ct.size() == 8, "empty input padded to one full block");
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(compareVector(rt, pt), "empty input round trip");
	}
	catch (...)
	{
		CHECK(0, "vector API empty input");
	}
	try
	{
		DES c, d;
		c.generateKeys(K3);
		d.generateKeys(K3);
		std::vector<uint8_t> pt = hexToVec("0011223344556677");
		std::vector<uint8_t> ct = c.encrypt(pt);
		ct[15] = 0x00;
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(rt.size() == 16, "invalid padding is not stripped");
	}
	catch (...)
	{
		CHECK(0, "vector API invalid padding");
	}

	/* DES takes a 64-bit key, i.e. exactly 16 hex characters. The check is
	   here rather than in a shared helper because DES is the one cipher whose
	   key is a single word. */
	printf("== key validation ==\n");
	{
		bool threw = false;
		try { DES c; c.generateKeys(std::string(16, '0')); }
		catch (std::invalid_argument &) { threw = true; }
		CHECK(!threw, "16 character key accepted");

		/* Every other length, including the multiples of 16 that a
		   hex-length check expressed in bytes would wrongly admit. */
		const size_t rejected[] = {0, 1, 8, 15, 17, 24, 32, 48, 64};
		for (size_t n : rejected)
		{
			threw = false;
			try { DES c; c.generateKeys(std::string(n, '0')); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu character key rejected", n);
			CHECK(threw, name);
		}
	}

	return alt.report();
}
