#include <vector>
#include <string>
#include <stdexcept>

#include "TestBase.h"
#include "vectors.h"
#include "block/Serpent.h"

class SerpentSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<Serpent> c(new Serpent());
		c->generateKeys(keyHex);
		return c;
	}
};

int main()
{
	/* The published single-block vectors, spanning all three key lengths and
	   the four NESSIE sets. The Python suite carries all sixteen; this is the
	   subset worth burning C++ build time on. */
	const char *K256 = SERPENT_K256;

	SerpentSuite suite;

	printf("== NESSIE known-answer tests ==\n");
	suite.runEcbKats(asKats(SERPENT_KATS));
	suite.runEcbKatsDec(asKats(SERPENT_KATS));

	printf("== ECB two blocks (nettle) ==\n");
	suite.runEcbKats(asKats(SERPENT_ECB));
	suite.runEcbKatsDec(asKats(SERPENT_ECB));
	for (const BlockKat &k : SERPENT_ECB)
	{
		/* ECB must not chain: encrypting block 2 alone gives the same bytes. */
		Serpent c;
		c.generateKeys(k.key);
		std::vector<uint8_t> pt = hexToVec(SERPENT_TWO_BLOCK_PT), ct = hexToVec(k.cipher);
		std::vector<uint8_t> tail(pt.begin() + 16, pt.end()), half(ct.begin() + 16, ct.end());
		c.encryptECB(&tail[0], (int)tail.size());
		char label[96];
		snprintf(label, sizeof(label), "%s block 2 stands alone", k.name.c_str());
		CHECK(compareVector(tail, half), label);
	}

	printf("== CBC two blocks (nettle) ==\n");
	{
		Serpent c;
		std::vector<uint8_t> pt = hexToVec(SERPENT_TWO_BLOCK_PT), ct = hexToVec(SERPENT_CBC[0].cipher), v = pt, iv = hexToVec(SERPENT_CBC_IV);
		c.generateKeys(SERPENT_CBC_KEY);
		c.encryptCBC(&v[0], (int)v.size(), &iv[0]);
		CHECK(compareVector(v, ct), "cbc two-block encrypt");

		/* CBC chains, so the two ciphertext blocks must differ. */
		std::vector<uint8_t> first(ct.begin(), ct.begin() + 16), second(ct.begin() + 16, ct.end());
		CHECK(!compareVector(first, second), "cbc two-block encrypt chains");

		/* decryptCBC advances the IV it is handed, so start from a fresh copy. */
		v = ct;
		iv = hexToVec(SERPENT_CBC_IV);
		c.decryptCBC(&v[0], (int)v.size(), &iv[0]);
		CHECK(compareVector(v, pt), "cbc two-block decrypt");
	}

	printf("== Word order (paper's little-endian bitslice words) ==\n");
	{
		/* Subkey 0 for the all-zero 256-bit key pins the whole convention at
		   once: little-endian loading of block and key words, the un-reversed
		   golden-ratio constant and the un-reversed round counter. A
		   bit-reversed reading of the same schedule gives different words.

		   No published table lists intermediate subkeys, so this is a regression
		   pin: the eight official ciphertexts above already constrain this
		   schedule, because any error in it changes the ciphertext. */
		static const uint32_t EXPECTED[4] = {
			0x6f5795d0u, 0xa7e3a3ceu, 0xf2d998edu, 0x8ed77390u,
		};
		Serpent c;
		c.generateKeys(std::string(64, '0'));
		bool ok = c.Subkeys.size() == 132;
		for (int i = 0; ok && i < 4; ++i)
			ok = c.Subkeys[i] == EXPECTED[i];
		CHECK(ok, "subkey 0 for the all-zero key is 0x6f5795d0 0xa7e3a3ce "
		          "0xf2d998ed 0x8ed77390");
	}

	printf("== ECB multi-block round trip ==\n");
	suite.runEcbRoundTrip(K256, 32, "Serpent");

	printf("== CBC round trip ==\n");
	{
		Serpent c, d;
		c.generateKeys("8000000000000000000000000000000000000000000000000000000000000000");
		d.generateKeys("8000000000000000000000000000000000000000000000000000000000000000");
		std::vector<uint8_t> v, w, iv, iv2;
		for (int i = 0; i < 32; ++i)
			v.push_back((uint8_t)(0xA0 + i));
		w = v;
		for (int i = 0; i < 16; ++i)
			iv.push_back(0x00);
		iv2 = iv;
		c.encryptCBC(&v[0], (int)v.size(), &iv[0]);
		CHECK(!compareVector(v, w), "cbc ciphertext differs from plaintext");
		d.decryptCBC(&v[0], (int)v.size(), &iv2[0]);
		CHECK(compareVector(v, w), "cbc encrypt+decrypt restores plaintext");
	}

	/* Serpent's specification accepts any key of 1 to 256 bits and defines the
	   padding for shorter ones, which padKeyBit implements, so short keys are
	   legal rather than an error. Only the two cases padKeyBit would paper over
	   are refused: the empty key, which it turned into "00", and an over-long
	   one, which it truncated to 64 characters without saying so.

	   Note this differs from Python, which rejects anything but 16, 24 and 32
	   bytes. C and Java agree with the specification and with nettle; Python is
	   the outlier here. */
	printf("== key length validation ==\n");
	{
		const size_t accepted[] = {1, 2, 3, 4, 8, 16, 24, 32, 48, 63, 64};
		for (size_t n : accepted)
		{
			bool threw = false;
			try { Serpent c; c.generateKeys(std::string(n, '0')); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			/* An odd count is a half byte, which padKeyBit rounds up to the
			   next whole byte before applying the spec's 0x01 padding, so
			   report the byte count it actually keys. */
			snprintf(name, sizeof(name), "%zu character key accepted (%zu-bit)", n, ((n + 1) / 2) * 8);
			CHECK(!threw, name);
		}

		const size_t rejected[] = {0, 65, 72, 128};
		for (size_t n : rejected)
		{
			bool threw = false;
			try { Serpent c; c.generateKeys(std::string(n, '0')); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu character key rejected", n);
			CHECK(threw, name);
		}
	}

	printf("== vector API / PKCS#7 padding ==\n");
	try
	{
		Serpent c, d;
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
		Serpent c;
		c.generateKeys(K256);
		std::vector<uint8_t> pt = hexToVec("ABCD");
		CHECK(c.encrypt(pt).size() == 16, "encrypt(vector) pads 2 bytes to one block");
	}
	catch (...)
	{
		CHECK(0, "vector API short input");
	}
	try
	{
		Serpent c, d;
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
		Serpent c, d;
		c.generateKeys(K256);
		d.generateKeys(K256);
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
