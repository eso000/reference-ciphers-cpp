#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <stdexcept>

#include "block/AES.h"

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

void printVec(std::vector<uint8_t> v)
{
	for (int i = 0; i < v.size(); ++i)
		printf("%02x", v[i]);
	printf("\n");
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

int aesEncrypt(const char *key, std::vector<uint8_t> in, std::vector<uint8_t> *out)
{
	try
	{
		AES c;
		c.generateKeys(key);
		*out = in;
		c.encrypt(&(*out)[0], out->size());
		return 1;
	}
	catch (...)
	{
		return 0;
	}
}

int aesDecrypt(const char *key, std::vector<uint8_t> in, std::vector<uint8_t> *out)
{
	try
	{
		AES c;
		c.generateKeys(key);
		*out = in;
		c.decrypt(&(*out)[0], out->size());
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
	int ok = aesEncrypt(key, hexToVec(plain), &got);
	CHECK(ok && compareVector(got, hexToVec(cipher)), name);
}

void runKatDec(const char *name, const char *key, const char *plain, const char *cipher)
{
	std::vector<uint8_t> got;
	int ok = aesDecrypt(key, hexToVec(cipher), &got);
	CHECK(ok && compareVector(got, hexToVec(plain)), name);
}

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

	printf("== FIPS-197 single block ==\n");
	runKat("fips-197 C.1 AES-128 encrypt", K128, P0, "69c4e0d86a7b0430d8cdb78070b4c55a");
	runKat("fips-197 C.2 AES-192 encrypt", K192, P0, "dda97ca4864cdfe06eaf70a0ec0d7191");
	runKat("fips-197 C.3 AES-256 encrypt", K256, P0, "8ea2b7ca516745bfeafc49904b496089");
	runKatDec("fips-197 C.1 AES-128 decrypt", K128, P0, "69c4e0d86a7b0430d8cdb78070b4c55a");
	runKatDec("fips-197 C.2 AES-192 decrypt", K192, P0, "dda97ca4864cdfe06eaf70a0ec0d7191");
	runKatDec("fips-197 C.3 AES-256 decrypt", K256, P0, "8ea2b7ca516745bfeafc49904b496089");

	printf("== NIST SP 800-38A ECB ==\n");
	runKat("sp800-38a ecb AES-128 encrypt", S128, SP, SC128);
	runKat("sp800-38a ecb AES-192 encrypt", S192, SP, SC192);
	runKat("sp800-38a ecb AES-256 encrypt", S256, SP, SC256);
	runKatDec("sp800-38a ecb AES-128 decrypt", S128, SP, SC128);
	runKatDec("sp800-38a ecb AES-192 decrypt", S192, SP, SC192);
	runKatDec("sp800-38a ecb AES-256 decrypt", S256, SP, SC256);

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
	{
		const char *kkeys[] = {K128, K192, K256};
		const char *labels[] = {"AES-128", "AES-192", "AES-256"};
		for (int s = 0; s < 3; ++s)
		{
			char name[96];
			AES c, d;
			c.generateKeys(kkeys[s]);
			d.generateKeys(kkeys[s]);
			std::vector<uint8_t> v, w;
			for (int i = 0; i < 32; ++i)
				v.push_back((uint8_t)(0xA5 + i));
			w = v;
			c.encrypt(&v[0], (int)v.size());
			snprintf(name, sizeof(name), "%s: ciphertext differs from plaintext", labels[s]);
			CHECK(!compareVector(v, w), name);
			d.decrypt(&v[0], (int)v.size());
			snprintf(name, sizeof(name), "%s: encrypt+decrypt restores plaintext", labels[s]);
			CHECK(compareVector(v, w), name);
		}
	}

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

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}