#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <stdexcept>

#include "block/Serpent.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

uint8_t compareVector(const std::vector<uint8_t> &v, const std::vector<uint8_t> &w)
{
	if (v.size() != w.size())
		return 0;
	for (size_t i = 0; i < v.size(); ++i)
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

int serpentEncrypt(const char *key, const std::vector<uint8_t> &in, std::vector<uint8_t> *out)
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

int serpentDecrypt(const char *key, const std::vector<uint8_t> &in, std::vector<uint8_t> *out)
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

/* The published single-block vectors, spanning all three key lengths and the
   four NESSIE sets. The Python suite in tests/vectors.py carries all sixteen;
   this is the subset worth burning C++ build time on. */
struct Kat
{
	const char *name;
	const char *key;
	const char *plain;
	const char *cipher;
};

static const Kat KATS[] = {
	{"128-bit set1 v0", "80000000000000000000000000000000",
		"00000000000000000000000000000000", "264e5481eff42a4606abda06c0bfda3d"},
	{"128-bit set4 v0", "000102030405060708090a0b0c0d0e0f",
		"00112233445566778899aabbccddeeff", "563e2cf8740a27c164804560391e9b27"},
	{"128-bit set4 v1", "2bd6459f82c5b300952c49104881ff48",
		"ea024714ad5c4d84ea024714ad5c4d84", "92d7f8ef2c36c53409f275902f06539f"},
	{"192-bit set1 v0", "800000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000", "9e274ead9b737bb21efcfca548602689"},
	{"192-bit set4 v0", "000102030405060708090a0b0c0d0e0f1011121314151617",
		"00112233445566778899aabbccddeeff", "6ab816c82de53b93005008afa2246a02"},
	{"256-bit set1 v0", "8000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0"},
	{"256-bit set3 v17", "1111111111111111111111111111111111111111111111111111111111111111",
		"11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2"},
	{"256-bit set4 v1", "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300952c49104881ff48",
		"ea024714ad5c4d84ea024714ad5c4d84", "3e507730776b93fdea661235e1dd99f0"},
};

/* Multi-block vectors. Serpent's published vectors are single-block ECB, so
   nothing published covers the mode wrappers; these were produced by GNU
   nettle and are the only expected values here that are not traceable to a
   numbered table. */
static const char *TWO_BLOCK_PT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

struct ModeKat
{
	const char *name;
	const char *key;
	const char *cipher;
};

static const ModeKat ECB_KATS[] = {
	{"128-bit", "000102030405060708090a0b0c0d0e0f",
		"4c7d8a328072a22c823e4a1f3acda16d1fe31aba9824fb1b33b42582291388db"},
	{"192-bit", "000102030405060708090a0b0c0d0e0f1011121314151617",
		"753d5b42d86672fb29070c4fe4eaaf4c4cc221270d91e743ca7b9d9e4e1ebe65"},
	{"256-bit", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"de269ff833e432b85b2e88d2701ce75ce534b936d9df2fc053bee5ed268fc68c"},
};

static const char *CBC_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char *CBC_IV = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char *CBC_CIPHER = "2aa5a2ff0c27a0f9590f6167e9e779d861fc6463d2e956091e91677d4f38860c";

int main()
{
	const char *K256 = "1111111111111111111111111111111111111111111111111111111111111111";

	printf("== NESSIE known-answer tests ==\n");
	for (const Kat &k : KATS)
	{
		char label[96];
		snprintf(label, sizeof(label), "kat %s encrypt", k.name);
		runKat(label, k.key, k.plain, k.cipher);
		snprintf(label, sizeof(label), "kat %s decrypt", k.name);
		runKatDec(label, k.key, k.plain, k.cipher);
	}

	printf("== ECB two blocks (nettle) ==\n");
	for (const ModeKat &k : ECB_KATS)
	{
		char label[96];
		std::vector<uint8_t> pt = hexToVec(TWO_BLOCK_PT), ct = hexToVec(k.cipher), got;

		snprintf(label, sizeof(label), "ecb two-block %s encrypt", k.name);
		CHECK(serpentEncrypt(k.key, pt, &got) && compareVector(got, ct), label);

		snprintf(label, sizeof(label), "ecb two-block %s decrypt", k.name);
		CHECK(serpentDecrypt(k.key, ct, &got) && compareVector(got, pt), label);

		/* ECB must not chain: encrypting block 2 alone gives the same bytes. */
		std::vector<uint8_t> tail(pt.begin() + 16, pt.end()), half(ct.begin() + 16, ct.end());
		snprintf(label, sizeof(label), "ecb two-block %s block 2 stands alone", k.name);
		CHECK(serpentEncrypt(k.key, tail, &got) && compareVector(got, half), label);
	}

	printf("== CBC two blocks (nettle) ==\n");
	{
		Serpent c;
		std::vector<uint8_t> pt = hexToVec(TWO_BLOCK_PT), ct = hexToVec(CBC_CIPHER), v = pt, iv = hexToVec(CBC_IV);
		c.generateKeys(CBC_KEY);
		c.encryptCBC(&v[0], (int)v.size(), &iv[0]);
		CHECK(compareVector(v, ct), "cbc two-block encrypt");

		/* CBC chains, so the two ciphertext blocks must differ. */
		std::vector<uint8_t> first(ct.begin(), ct.begin() + 16), second(ct.begin() + 16, ct.end());
		CHECK(!compareVector(first, second), "cbc two-block encrypt chains");

		/* decryptCBC advances the IV it is handed, so start from a fresh copy. */
		v = ct;
		iv = hexToVec(CBC_IV);
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
