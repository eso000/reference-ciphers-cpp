#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "block/AES.h"
#include "block/Blowfish.h"
#include "block/Twofish.h"
#include "block/DES.h"
#include "block/Serpent.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

static int compareVector(const std::vector<uint8_t>& v, const std::vector<uint8_t>& w)
{
	if (v.size() != w.size())
		return 0;
	for (size_t i = 0; i < v.size(); ++i)
		if (v[i] != w[i])
			return 0;
	return 1;
}

static std::vector<uint8_t> hexToVec(const char *hex)
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

static void runCipher(const char *name, BlockCipher& c, BlockCipher& d)
{
	int bs = c.blockSize();

	std::vector<uint8_t> pt;
	for (int i = 0; i < 3 * bs + 5; ++i)
		pt.push_back((uint8_t)(0x30 + (i * 7) % 200));

	std::vector<uint8_t> iv;
	for (int i = 0; i < bs; ++i)
		iv.push_back((uint8_t)(0x11 * (i + 1)));

	const BlockMode modes[] = {BlockMode::ECB, BlockMode::CBC, BlockMode::PCBC,
	                           BlockMode::CFB, BlockMode::OFB, BlockMode::CTR};
	const char *modeNames[] = {"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"};
	const Padding pads[] = {Padding::PKCS7, Padding::ANSIX923, Padding::ISO78164};
	const char *padNames[] = {"PKCS7", "ANSIX923", "ISO78164"};

	for (int m = 0; m < 6; ++m)
	{
		for (int p = 0; p < 3; ++p)
		{
			char label[128];
			snprintf(label, sizeof(label), "%s %s + %s round trip", name, modeNames[m], padNames[p]);

			std::vector<uint8_t> ct = c.encryptMode(pt, modes[m], pads[p], iv);
			std::vector<uint8_t> rt = d.decryptMode(ct, modes[m], pads[p], iv);
			CHECK(compareVector(rt, pt), label);
		}
	}

	char label[128];
	snprintf(label, sizeof(label), "%s CBC + Zeros preserves data prefix", name);

	std::vector<uint8_t> ct = c.encryptMode(pt, BlockMode::CBC, Padding::Zeros, iv);
	std::vector<uint8_t> rt = d.decryptMode(ct, BlockMode::CBC, Padding::Zeros, iv);
	int prefixOk = rt.size() >= pt.size() && memcmp(&rt[0], &pt[0], pt.size()) == 0;
	int zeroOk = 1;
	for (size_t i = pt.size(); i < rt.size(); ++i)
		if (rt[i] != 0)
			zeroOk = 0;
	CHECK(prefixOk && zeroOk, label);
}

int main()
{
	printf("== generic block modes / paddings ==\n");

	{
		AES c, d;
		c.generateKeys("000102030405060708090a0b0c0d0e0f");
		d.generateKeys("000102030405060708090a0b0c0d0e0f");
		runCipher("AES", c, d);
	}
	{
		Blowfish c, d;
		c.generateKeys(hexToVec("0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef"));
		runCipher("Blowfish", c, d);
	}
	{
		Twofish c, d;
		c.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		runCipher("Twofish", c, d);
	}
	{
		DES c, d;
		c.generateKeys("133457799BBCDFF1");
		d.generateKeys("133457799BBCDFF1");
		runCipher("DES", c, d);
	}
	{
		Serpent c, d;
		c.generateKeys("000102030405060708090a0b0c0d0e0f");
		d.generateKeys("000102030405060708090a0b0c0d0e0f");
		runCipher("Serpent", c, d);
	}

	printf("== mode output differs from ECB ==\n");
	{
		AES c, d;
		c.generateKeys("000102030405060708090a0b0c0d0e0f");
		d.generateKeys("000102030405060708090a0b0c0d0e0f");
		std::vector<uint8_t> pt = hexToVec("00112233445566778899aabbccddeeff");
		std::vector<uint8_t> iv;
		for (int i = 0; i < 16; ++i)
			iv.push_back((uint8_t)(0x5a + i));
		std::vector<uint8_t> ecb = c.encryptMode(pt, BlockMode::ECB, Padding::None);
		std::vector<uint8_t> cbc = c.encryptMode(pt, BlockMode::CBC, Padding::None, iv);
		CHECK(!compareVector(ecb, cbc), "AES ECB and CBC differ on identical input");
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
