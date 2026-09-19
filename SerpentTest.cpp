#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "Serpent.h"

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

std::vector<uint8_t> hexToVec(const char *hex)
{
	std::vector<uint8_t> v;
	int n = strlen(hex) / 2;
	for (int i = 0; i < n; ++i)
	{
		unsigned x;
		sscanf(hex + 2 * i, "%2x", &x);
		v.push_back((uint8_t)x);
	}
	return v;
}

int serpentEncrypt(const char *key, std::vector<uint8_t> in, std::vector<uint8_t> *out)
{
	try
	{
		Serpent c;
		c.generateKeys(key);
		*out = in;
		c.encryptECB(&(*out)[0], out->size());
		return 1;
	}
	catch (...)
	{
		return 0;
	}
}

int serpentDecrypt(const char *key, std::vector<uint8_t> in, std::vector<uint8_t> *out)
{
	try
	{
		Serpent c;
		c.generateKeys(key);
		*out = in;
		c.decryptECB(&(*out)[0], out->size());
		return 1;
	}
	catch (...)
	{
		return 0;
	}
}

void runKat(const char *name, const char *key, const char *plain, const char *cipher)
{
	std::vector<uint8_t> got;
	int ok = serpentEncrypt(key, hexToVec(plain), &got);
	CHECK(ok && compareVector(got, hexToVec(cipher)), name);
}

void runKatDec(const char *name, const char *key, const char *plain, const char *cipher)
{
	std::vector<uint8_t> got;
	int ok = serpentDecrypt(key, hexToVec(cipher), &got);
	CHECK(ok && compareVector(got, hexToVec(plain)), name);
}

int main()
{
	const char *K256 = "1111111111111111111111111111111111111111111111111111111111111111";
	const char *P0 = "00112233445566778899aabbccddeeff";

	printf("== NESSIE set 1 known-answer tests ==\n");
	runKat("kat 1 encrypt", "8000000000000000000000000000000000000000000000000000000000000000",
		   "00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0");
	runKatDec("kat 1 decrypt", "8000000000000000000000000000000000000000000000000000000000000000",
			  "00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0");
	runKat("kat 2 encrypt", K256, "11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2");
	runKatDec("kat 2 decrypt", K256, "11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2");

	printf("== 128/192-bit key known-answer tests ==\n");
	runKat("kat 128-bit encrypt", "0102030405060708090a0b0c0d0e0f10", P0, "74bfd1dad54afd5f8eb3ae1fb0064d42");
	runKatDec("kat 128-bit decrypt", "0102030405060708090a0b0c0d0e0f10", P0, "74bfd1dad54afd5f8eb3ae1fb0064d42");
	runKat("kat 192-bit encrypt", "0102030405060708090a0b0c0d0e0f101112131415161718", P0, "de97dc8dfef97afc46d5d028397ec07f");
	runKatDec("kat 192-bit decrypt", "0102030405060708090a0b0c0d0e0f101112131415161718", P0, "de97dc8dfef97afc46d5d028397ec07f");

	printf("== ECB multi-block round trip ==\n");
	{
		Serpent c, d;
		c.generateKeys(K256);
		d.generateKeys(K256);
		std::vector<uint8_t> v, w;
		for (int i = 0; i < 32; ++i)
			v.push_back((uint8_t)(0x10 + i));
		w = v;
		c.encryptECB(&v[0], (int)v.size());
		CHECK(!compareVector(v, w), "ecb ciphertext differs from plaintext");
		d.decryptECB(&v[0], (int)v.size());
		CHECK(compareVector(v, w), "ecb encrypt+decrypt restores plaintext");
	}

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
		std::vector<uint8_t> rt = d.decrypt(ct);
		CHECK(rt.size() == 32, "invalid padding is not stripped");
	}
	catch (...)
	{
		CHECK(0, "vector API invalid padding");
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
