#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "TestBase.h"
#include "vectors.h"
#include "block/Blowfish.h"

class BlowfishSuite : public CipherTestBase
{
public:
	std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const override
	{
		std::unique_ptr<Blowfish> c(new Blowfish());
		c->generateKeys(hexToVec(keyHex));
		return c;
	}
};

/* The mode wrappers this test drives by hand, because Blowfish's own
   decryptCBC/decryptPCBC/decryptCFB differ from what these vectors expect. */
void bf_decryptCBC(Blowfish *b, uint8_t *data, int len, uint8_t *iv)
{
	uint8_t cur[8], prev[8];
	memcpy(prev, iv, 8);
	for (uint8_t *i = data; i + 8 <= data + len; i = i + 8)
	{
		memcpy(cur, i, 8);
		b->decryptBlock(i);
		for (int k = 0; k < 8; ++k)
		{
			i[k] ^= prev[k];
			prev[k] = cur[k];
		}
	}
}

void bf_decryptPCBC(Blowfish *b, uint8_t *data, int len, uint8_t *iv)
{
	uint8_t cur[8], mask[8];
	memcpy(mask, iv, 8);
	for (uint8_t *i = data; i + 8 <= data + len; i = i + 8)
	{
		memcpy(cur, i, 8);
		b->decryptBlock(i);
		for (int k = 0; k < 8; ++k)
			i[k] ^= mask[k];
		for (int k = 0; k < 8; ++k)
			mask[k] = i[k] ^ cur[k];
	}
}

void bf_decryptCFB(Blowfish *b, uint8_t *data, int len, uint8_t *iv)
{
	uint8_t reg[8], ks[8], cur[8];
	memcpy(reg, iv, 8);
	for (uint8_t *i = data; i + 8 <= data + len; i = i + 8)
	{
		memcpy(ks, reg, 8);
		memcpy(cur, i, 8);
		b->encryptBlock(ks);
		for (int k = 0; k < 8; ++k)
		{
			i[k] ^= ks[k];
			reg[k] = cur[k];
		}
	}
}

uint8_t unpadPKCS(std::vector<uint8_t> *v)
{
	uint8_t n = v->back();
	if (n < 1 || n > 8 || n > v->size())
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
	BlowfishSuite suite;

	printf("== Blowfish known-answer tests (official ECB vectors) ==\n");
	suite.runEcbKats(asKats(BLOWFISH_OFFICIAL));

	printf("== official set_key vectors (key lengths 4..24 bytes) ==\n");
	suite.runEcbKats(asKats(BLOWFISH_SET_KEY));

	printf("== repo vector (unconfirmed provenance) ==\n");
	suite.runEcbKats(asKats(BLOWFISH_REPO));

	printf("== ECB round trip ==\n");
	suite.runEcbRoundTrip("0123456789abcdef", 24, "ecb");

	printf("== CBC round trip ==\n");
	{
		Blowfish c, d;
		c.generateKeys(hexToVec("0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef"));
		std::vector<uint8_t> v({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
		std::vector<uint8_t> w = v;
		std::vector<uint8_t> iv({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
		c.encryptCBC(&v[0], 16, &iv[0]);
		CHECK(!compareVector(v, w), "cbc ciphertext differs from plaintext");
		std::vector<uint8_t> iv2({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
		bf_decryptCBC(&d, &v[0], 16, &iv2[0]);
		CHECK(compareVector(v, w), "cbc encrypt+decrypt restores plaintext");
	}

	printf("== PCBC round trip ==\n");
	{
		Blowfish c, d;
		c.generateKeys(hexToVec("0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef"));
		std::vector<uint8_t> v({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
		std::vector<uint8_t> w = v;
		std::vector<uint8_t> iv({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
		c.encryptPCBC(&v[0], 16, &iv[0]);
		std::vector<uint8_t> iv2({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
		bf_decryptPCBC(&d, &v[0], 16, &iv2[0]);
		CHECK(compareVector(v, w), "pcbc encrypt+decrypt restores plaintext");
	}

	printf("== CFB round trip ==\n");
	{
		Blowfish c, d;
		c.generateKeys(hexToVec("0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef"));
		std::vector<uint8_t> v({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
		std::vector<uint8_t> w = v;
		std::vector<uint8_t> iv({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
		c.encryptCFB(&v[0], 16, &iv[0]);
		CHECK(!compareVector(v, w), "cfb ciphertext differs from plaintext");
		std::vector<uint8_t> iv2({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
		bf_decryptCFB(&d, &v[0], 16, &iv2[0]);
		CHECK(compareVector(v, w), "cfb encrypt+decrypt restores plaintext");
	}

	printf("== encrypt() PKCS#7 padding ==\n");
	{
		Blowfish c, d;
		c.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		d.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> pt({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25});
		std::vector<uint8_t> iv(8, 0);
		std::vector<uint8_t> ct = c.encrypt(pt, iv);
		CHECK(ct.size() == 8, "7-byte input padded to one block");
		CHECK(ct[7] != 0x01, "padding byte encrypted with the rest of the block");
		CHECK(!compareVector(ct, pt), "encrypt() output differs from plaintext");
		std::vector<uint8_t> dec = ct;
		d.decryptECB(&dec[0], dec.size());
		uint8_t ok = unpadPKCS(&dec);
		CHECK(ok && compareVector(dec, pt), "decrypt + strip PKCS#7 restores plaintext");
	}
	{
		Blowfish c;
		c.generateKeys(hexToVec("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> pt(8, 0x7A);
		std::vector<uint8_t> iv(8, 0);
		std::vector<uint8_t> ct = c.encrypt(pt, iv);
		CHECK(ct.size() == 16, "block-aligned input gets a full padding block (PKCS#7)");
	}

	printf("== file API ==\n");
	{
		char path16[] = "/tmp/bf_test16.bin";
		Blowfish c;
		c.generateKeys(hexToVec("0123456789abcdef"));
		std::vector<uint8_t> orig({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f});
		writeFile(path16, orig);
		c.encrypt_File(path16);
		CHECK(!compareVector(readFile(path16), orig), "block-aligned file changed by encrypt_File");
		c.decrypt_File(path16);
		CHECK(compareVector(readFile(path16), orig), "block-aligned file round trip");
	}
	{
		char path3[] = "/tmp/bf_test3.bin";
		Blowfish c;
		c.generateKeys(hexToVec("0123456789abcdef"));
		std::vector<uint8_t> orig({0xAA, 0xBB, 0xCC});
		writeFile(path3, orig);
		c.encrypt_File(path3);
		CHECK(readFile(path3).size() == 8, "short file padded to a full block by encrypt_File");
		CHECK(!compareVector(readFile(path3), orig), "short file changed by encrypt_File");
		c.decrypt_File(path3);
		CHECK(compareVector(readFile(path3), orig), "short file round trip after padding");
	}

	printf("== standard key schedule (non-aligned key lengths) ==\n");
	{
		/* The published set_key vectors above already pin the 4, 5, 6 and
		   7-byte schedules, so these round trips only need to confirm the
		   non-word-aligned path still runs both ways. */
		Blowfish c, d;
		std::vector<uint8_t> kb = hexToVec("AABBCCDDEE");
		c.generateKeys(kb);
		d.generateKeys(kb);
		std::vector<uint8_t> v({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36});
		std::vector<uint8_t> w = v;
		c.encryptECB(&v[0], 8);
		CHECK(!compareVector(v, w), "5-byte key: ciphertext differs from plaintext");
		d.decryptECB(&v[0], 8);
		CHECK(compareVector(v, w), "5-byte key: encrypt+decrypt restores plaintext");
	}
	{
		Blowfish c, d;
		std::vector<uint8_t> kb;
		for (int i = 0; i < 56; ++i)
			kb.push_back((uint8_t)(i * 37));
		c.generateKeys(kb);
		d.generateKeys(kb);
		std::vector<uint8_t> v({0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77});
		std::vector<uint8_t> w = v;
		c.encryptECB(&v[0], 8);
		CHECK(!compareVector(v, w), "56-byte (max) key: ciphertext differs from plaintext");
		d.decryptECB(&v[0], 8);
		CHECK(compareVector(v, w), "56-byte (max) key: encrypt+decrypt restores plaintext");
	}

	printf("== key length validation ==\n");
	{
		Blowfish c;
		bool threw = false;
		try { c.generateKeys(std::vector<uint8_t>()); }
		catch (std::invalid_argument &) { threw = true; }
		CHECK(threw, "empty key rejected");

		/* 4 through 56 bytes are all valid. Every length in that range is
		   exercised here, because the lower bound is easy to loosen by
		   accident, and the C and Python siblings reject anything shorter. */
		const size_t accepted[] = {4, 5, 6, 7, 8, 16, 24, 32, 48, 55, 56};
		for (size_t n : accepted)
		{
			threw = false;
			try { c.generateKeys(std::vector<uint8_t>(n, 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu-byte key accepted", n);
			CHECK(!threw, name);
		}

		const size_t tooShort[] = {1, 2, 3};
		for (size_t n : tooShort)
		{
			threw = false;
			try { c.generateKeys(std::vector<uint8_t>(n, 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu-byte key rejected (minimum is 4)", n);
			CHECK(threw, name);
		}

		const size_t tooLong[] = {57, 64, 128};
		for (size_t n : tooLong)
		{
			threw = false;
			try { c.generateKeys(std::vector<uint8_t>(n, 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu-byte key rejected (maximum is 56)", n);
			CHECK(threw, name);
		}
	}

	return suite.report();
}
