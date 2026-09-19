#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "Twofish.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

uint8_t compareVector(std::vector<uint8_t> v, std::vector<uint8_t> w)
{
	if (v.size() != w.size())
		return 0;
	for (int i = 0; i < v.size(); ++i)
		if (v[i] != w[i])
			return 0;
	return 1;
}

void printHex(std::vector<uint8_t> v)
{
	for (int i = 0; i < v.size(); ++i)
		printf("%02x", v[i]);
	printf("\n");
}

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

std::vector<uint8_t> hexDecode(const char *hex)
{
	std::vector<uint8_t> v;
	for (int i = 0; hex[2 * i] && hex[2 * i + 1]; ++i)
	{
		unsigned x;
		sscanf(hex + 2 * i, "%2x", &x);
		v.push_back((uint8_t)x);
	}
	return v;
}

struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

void runKat(std::vector<Kat> kats, const char *label)
{
	char name[96];
	for (int i = 0; i < kats.size(); ++i)
	{
		Twofish c;
		c.generateKeys(hexDecode(kats[i].key));
		std::vector<uint8_t> v = hexDecode(kats[i].plain);
		std::vector<uint8_t> expected = hexDecode(kats[i].cipher);
		c.encryptECB(&v[0], 16);
		snprintf(name, sizeof(name), "%s %02d: %s / %s", label, i + 1, kats[i].key, kats[i].plain);
		CHECK(compareVector(v, expected), name);
	}
}

void runKatDec(std::vector<Kat> kats, const char *label)
{
	char name[96];
	for (int i = 0; i < kats.size(); ++i)
	{
		Twofish c;
		c.generateKeys(hexDecode(kats[i].key));
		std::vector<uint8_t> v = hexDecode(kats[i].cipher);
		std::vector<uint8_t> expected = hexDecode(kats[i].plain);
		c.decryptECB(&v[0], 16);
		snprintf(name, sizeof(name), "%s %02d: ciphertext back to plaintext", label, i + 1);
		CHECK(compareVector(v, expected), name);
	}
}

std::vector<Kat> officialKats()
{
	std::vector<Kat> k;
	/* Twofish book, appendix B.2 / official KAT set */
	k.push_back(Kat{"00000000000000000000000000000000", "00000000000000000000000000000000", "9F589F5CF6122C32B6BFEC2F2AE8C35A"});
	k.push_back(Kat{"00000000000000000000000000000000", "9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419"});
	k.push_back(Kat{"9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419", "019F9809DE1711858FAAC3A3BA20FBC3"});
	k.push_back(Kat{"88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44", "39DA69D6BA4997D585B6DC073CA341B2", "182B02D81497EA45F9DAACDC29193A65"});
	k.push_back(Kat{"D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F", "90AFE91BB288544F2C32DC239B2635E6", "6CB4561C40BF0A9705931CB6D408E7FA"});
	return k;
}

int main()
{
	printf("== Twofish known-answer tests (official ECB vectors) ==\n");
	runKat(officialKats(), "official ecb");
	runKatDec(officialKats(), "official ecb decrypt");

	printf("== ECB round trip (all three key sizes) ==\n");
	{
		std::vector<std::vector<uint8_t>> keys;
		keys.push_back(hexDecode("000102030405060708090A0B0C0D0E0F"));
		keys.push_back(hexDecode("000102030405060708090A0B0C0D0E0F1011121314151617"));
		keys.push_back(hexDecode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
		const char *labels[] = {"128-bit key", "192-bit key", "256-bit key"};
		for (int s = 0; s < 3; ++s)
		{
			Twofish c, d;
			c.generateKeys(keys[s]);
			d.generateKeys(keys[s]);
			std::vector<uint8_t> v, w;
			for (int i = 0; i < 32; ++i)
				v.push_back((uint8_t)(0xA5 + i));
			w = v;
			c.encryptECB(&v[0], 32);
			char name[96];
			snprintf(name, sizeof(name), "%s: ciphertext differs from plaintext", labels[s]);
			CHECK(!compareVector(v, w), name);
			d.decryptECB(&v[0], 32);
			snprintf(name, sizeof(name), "%s: encrypt+decrypt restores plaintext", labels[s]);
			CHECK(compareVector(v, w), name);
		}
	}

	printf("== CBC round trip ==\n");
	{
		Twofish c, d;
		c.generateKeys(hexDecode("0123456789abcdef0123456789abcdef"));
		d.generateKeys(hexDecode("0123456789abcdef0123456789abcdef"));
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
		c.generateKeys(hexDecode("00112233445566778899aabbccddeeff"));
		d.generateKeys(hexDecode("00112233445566778899aabbccddeeff"));
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
		c.generateKeys(hexDecode("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> pt(16, 0x7A);
		std::vector<uint8_t> iv(16, 0);
		std::vector<uint8_t> ct = c.encrypt(pt, iv);
		CHECK(ct.size() == 32, "block-aligned input gets a full padding block (PKCS#7)");
	}
	{
		Twofish c;
		c.generateKeys(hexDecode("00112233445566778899aabbccddeeff"));
		std::vector<uint8_t> iv(16, 0);
		std::vector<uint8_t> ct = c.encrypt(std::vector<uint8_t>(), iv);
		CHECK(ct.size() == 16, "empty input padded to one full block");
	}

	printf("== file API (ECB) ==\n");
	{
		char path16[] = "/tmp/tf_test16.bin";
		Twofish c;
		c.generateKeys(hexDecode("0123456789abcdef0123456789abcdef"));
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
		c.generateKeys(hexDecode("0123456789abcdef0123456789abcdef"));
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
		c.generateKeys(hexDecode("0123456789abcdef0123456789abcdef"));
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

	printf("== key length validation ==\n");
	{
		int bad[] = {0, 8, 15, 17, 40};
		const char *badName[] = {"empty key rejected", "8-byte key rejected", "15-byte key rejected", "17-byte key rejected", "40-byte key rejected"};
		for (int t = 0; t < 5; ++t)
		{
			Twofish c;
			bool threw = false;
			try { c.generateKeys(std::vector<uint8_t>(bad[t], 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			CHECK(threw, badName[t]);
		}
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}