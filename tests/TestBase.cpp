#include "TestBase.h"

using block::BlockCipher;

int g_fails = 0;

std::vector<uint8_t> hexToVec(const char *hex)
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

bool compareVector(const std::vector<uint8_t> &v, const std::vector<uint8_t> &w)
{
	if (v.size() != w.size())
		return false;
	for (size_t i = 0; i < v.size(); ++i)
		if (v[i] != w[i])
			return false;
	return true;
}

void printVec(const std::vector<uint8_t> &v)
{
	for (size_t i = 0; i < v.size(); ++i)
		printf("%02x", v[i]);
	printf("\n");
}

void CipherTestBase::runEcbKats(const std::vector<BlockKat> &kats)
{
	for (const BlockKat &k : kats)
	{
		std::unique_ptr<BlockCipher> c = makeKeyed(k.key);
		std::vector<uint8_t> got = hexToVec(k.plain);
		c->encryptECB(got);
		std::string name = k.name + " encrypt";
		CHECK(compareVector(got, hexToVec(k.cipher)), name.c_str());
	}
}

void CipherTestBase::runEcbKatsDec(const std::vector<BlockKat> &kats)
{
	for (const BlockKat &k : kats)
	{
		std::unique_ptr<BlockCipher> c = makeKeyed(k.key);
		std::vector<uint8_t> got = hexToVec(k.cipher);
		c->decryptECB(got);
		std::string name = k.name + " decrypt";
		CHECK(compareVector(got, hexToVec(k.plain)), name.c_str());
	}
}

void CipherTestBase::runEcbRoundTrip(const char *keyHex, int len, const char *label)
{
	std::unique_ptr<BlockCipher> c = makeKeyed(keyHex);
	std::unique_ptr<BlockCipher> d = makeKeyed(keyHex);

	std::vector<uint8_t> v, w;
	for (int i = 0; i < len; ++i)
		v.push_back((uint8_t)(0xA5 + i));
	w = v;

	char name[160];
	c->encryptECB(v);
	snprintf(name, sizeof(name), "%s ciphertext differs from plaintext", label);
	CHECK(!compareVector(v, w), name);

	d->decryptECB(v);
	snprintf(name, sizeof(name), "%s encrypt+decrypt restores plaintext", label);
	CHECK(compareVector(v, w), name);
}

int CipherTestBase::report()
{
	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
