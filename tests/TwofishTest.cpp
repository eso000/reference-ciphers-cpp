#include <vector>
#include <string>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "TestBase.h"
#include "vectors.h"
#include "block/Twofish.h"

class TwofishSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<Twofish> c(new Twofish());
		c->generateKeys(hexToVec(keyHex));
		return c;
	}
};

uint8_t unpadPKCS(std::vector<uint8_t> *v)
{
	uint8_t n = v->back();
	if (n < 1 || n > 16 || n > v->size())
		return 0;
	for (int i = 0; i < n; ++i)
		if ((*v)[v->size() - 1 - i] != n)
			return 0;
	v->resize(v->size() - n);
	return 1;
}

std::vector<uint8_t> readFile(const char *path)
{
	std::ifstream input_file(path, std::ios::binary);
	std::vector<uint8_t> vec((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
	input_file.close();
	return vec;
}

void writeFile(const char *path, std::vector<uint8_t> v)
{
	std::ofstream file(path, std::ios::binary);
	file.write(reinterpret_cast<char *>(&v[0]), v.size());
	file.close();
}

int main()
{
	TwofishSuite suite;

	printf("== Twofish known-answer tests (official ECB vectors) ==\n");
	suite.runEcbKats(asKats(TWOFISH_KATS));
	suite.runEcbKatsDec(asKats(TWOFISH_KATS));

	printf("== ECB round trip (all three key sizes) ==\n");
	suite.runEcbRoundTrip("000102030405060708090A0B0C0D0E0F", 32, "128-bit key");
	suite.runEcbRoundTrip("000102030405060708090A0B0C0D0E0F1011121314151617", 32, "192-bit key");
	suite.runEcbRoundTrip("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", 32, "256-bit key");

	printf("== CBC round trip ==\n");
	{
		Twofish c, d;
		c.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		std::vector<uint8_t> v({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f});
		std::vector<uint8_t> w = v;
		std::vector<uint8_t> iv(16, 0xAA);
		c.encryptCBC(&v[0], 32, &iv[0]);
		CHECK(!compareVector(v, w), "cbc two-block ciphertext differs from plaintext");
		std::vector<uint8_t> iv2(16, 0xAA);
		d.decryptCBC(&v[0], 32, &iv2[0]);
		CHECK(compareVector(v, w), "cbc two-block encrypt+decrypt restores plaintext");
	}

	printf("== encrypt() PKCS#7 padding (16-byte blocks) ==\n");
	{
		Twofish c, d;
		c.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		d.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> pt({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25});
		std::vector<uint8_t> iv(16, 0);
		std::vector<uint8_t> ct = c.encrypt(pt, iv);
		CHECK(ct.size() == 16, "7-byte input padded to one block");
		CHECK(ct[15] != 0x09, "padding byte encrypted with the rest of the block");
		CHECK(!compareVector(ct, pt), "encrypt() output differs from plaintext");
		std::vector<uint8_t> dec = ct;
		std::vector<uint8_t> iv2(16, 0);
		d.decryptCBC(&dec[0], (int)dec.size(), &iv2[0]);
		uint8_t ok = unpadPKCS(&dec);
		CHECK(ok && compareVector(dec, pt), "decrypt + strip PKCS#7 restores plaintext");
	}
	{
		Twofish c;
		c.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> pt(16, 0x7A);
		std::vector<uint8_t> iv(16, 0);
		std::vector<uint8_t> ct = c.encrypt(pt, iv);
		CHECK(ct.size() == 32, "block-aligned input gets a full padding block (PKCS#7)");
	}
	{
		Twofish c;
		c.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> iv(16, 0);
		std::vector<uint8_t> ct = c.encrypt(std::vector<uint8_t>(), iv);
		CHECK(ct.size() == 16, "empty input padded to one full block");
	}

	printf("== file API (ECB) ==\n");
	{
		char path16[] = "/tmp/tf_test16.bin";
		Twofish c;
		c.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		std::vector<uint8_t> orig;
		for (int i = 0; i < 32; ++i)
			orig.push_back((uint8_t)(0x10 + i));
		writeFile(path16, orig);
		c.encrypt_File(path16);
		CHECK(!compareVector(readFile(path16), orig), "block-aligned file changed by encrypt_File");
		c.decrypt_File(path16);
		CHECK(compareVector(readFile(path16), orig), "block-aligned file round trip");
	}
	{
		char path3[] = "/tmp/tf_test3.bin";
		Twofish c;
		c.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		std::vector<uint8_t> orig({0xAA, 0xBB, 0xCC});
		writeFile(path3, orig);
		c.encrypt_File(path3);
		CHECK(readFile(path3).size() == 16, "short file padded to a full block by encrypt_File");
		CHECK(!compareVector(readFile(path3), orig), "short file changed by encrypt_File");
	}

	printf("== file API (CBC) ==\n");
	{
		char path[] = "/tmp/tf_testcbc.bin";
		Twofish c;
		c.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		std::vector<uint8_t> orig;
		for (int i = 0; i < 32; ++i)
			orig.push_back((uint8_t)(0x30 + i));
		writeFile(path, orig);
		c.mode = 1;
		c.encrypt_File(path);
		CHECK(!compareVector(readFile(path), orig), "cbc mode: file changed by encrypt_File");
		c.decrypt_File(path);
		CHECK(compareVector(readFile(path), orig), "cbc mode: file round trip");
	}

	/* Twofish takes a 128, 192 or 256-bit key. The check existed already; the
	   point of adding the accepted lengths is that a range check could be
	   widened without any of these failing. */
	printf("== key length validation ==\n");
	{
		const size_t accepted[] = {16, 24, 32};
		for (size_t n : accepted)
		{
			Twofish c;
			bool threw = false;
			try { c.generateKeys(std::vector<uint8_t>(n, 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu-byte key accepted (Twofish-%d)", n, (int)(n / 2) * 8);
			CHECK(!threw, name);
		}

		const size_t rejected[] = {0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 40, 64};
		for (size_t n : rejected)
		{
			Twofish c;
			bool threw = false;
			try { c.generateKeys(std::vector<uint8_t>(n, 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu-byte key rejected", n);
			CHECK(threw, name);
		}
	}

	return suite.report();
}
