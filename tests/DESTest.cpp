#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <stdexcept>

#include "block/DES.h"

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

int desEncrypt(const char *key, std::vector<uint8_t> in, std::vector<uint8_t> *out, bool alt = true)
{
	try
	{
		DES c(alt);
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

int desDecrypt(const char *key, std::vector<uint8_t> in, std::vector<uint8_t> *out, bool alt = true)
{
	try
	{
		DES c(alt);
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

void runKat(const char *name, const char *key, const char *plain, const char *cipher, bool alt = true)
{
	std::vector<uint8_t> got;
	int ok = desEncrypt(key, hexToVec(plain), &got, alt);
	CHECK(ok && compareVector(got, hexToVec(cipher)), name);
}

void runKatDec(const char *name, const char *key, const char *plain, const char *cipher, bool alt = true)
{
	std::vector<uint8_t> got;
	int ok = desDecrypt(key, hexToVec(cipher), &got, alt);
	CHECK(ok && compareVector(got, hexToVec(plain)), name);
}

int main()
{
	const char *K1 = "133457799BBCDFF1";
	const char *K2 = "0E329232EA6D0D73";
	const char *K3 = "AABB09182736CCDD";

	printf("== standard DES known-answer tests (both IP/FP implementations) ==\n");
	for (int ai = 0; ai < 2; ++ai)
	{
		const char *mode = ai ? "alt" : "naive";
		char name[128];
		snprintf(name, sizeof(name), "kat 1 encrypt (%s)", mode);
		runKat(name, K1, "0123456789ABCDEF", "85E813540F0AB405", ai);
		snprintf(name, sizeof(name), "kat 1 decrypt (%s)", mode);
		runKatDec(name, K1, "0123456789ABCDEF", "85E813540F0AB405", ai);
		snprintf(name, sizeof(name), "kat 2 encrypt (%s)", mode);
		runKat(name, K2, "8787878787878787", "0000000000000000", ai);
		snprintf(name, sizeof(name), "kat 2 decrypt (%s)", mode);
		runKatDec(name, K2, "8787878787878787", "0000000000000000", ai);
		snprintf(name, sizeof(name), "kat 3 encrypt (%s)", mode);
		runKat(name, K3, "123456ABCD132536", "C0B7A8D05F3A829C", ai);
		snprintf(name, sizeof(name), "kat 3 decrypt (%s)", mode);
		runKatDec(name, K3, "123456ABCD132536", "C0B7A8D05F3A829C", ai);
	}

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
	{
		DES c, d;
		c.generateKeys(K3);
		d.generateKeys(K3);
		std::vector<uint8_t> v, w;
		for (int i = 0; i < 16; ++i)
			v.push_back((uint8_t)(0x10 + i));
		w = v;
		c.encryptECB(&v[0], (int)v.size());
		CHECK(!compareVector(v, w), "ecb ciphertext differs from plaintext");
		d.decryptECB(&v[0], (int)v.size());
		CHECK(compareVector(v, w), "ecb encrypt+decrypt restores plaintext");
	}

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

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
