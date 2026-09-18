#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

#include "Blowfish.h"

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

void bf_decryptCBC(Blowfish *b, uint8_t *data, int len, uint8_t *iv)
{
	uint8_t cur[8], prev[8];
	memcpy(prev, iv, 8);
	for (uint8_t *i = data; i + 8 <= data + len; i = i + 8)
	{
		memcpy(cur, i, 8);
		b->decrypt_block(i, i + 4);
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
		b->decrypt_block(i, i + 4);
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
		b->encrypt_block(ks, ks + 4);
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

struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

std::vector<uint8_t> hexToVec(const char *hex)
{
	std::vector<uint8_t> v;
	for (int i = 0; i < 8; ++i)
	{
		unsigned x;
		sscanf(hex + 2 * i, "%2x", &x);
		v.push_back((uint8_t)x);
	}
	return v;
}

void runKat(std::vector<Kat> kats, const char *label)
{
	char name[96];
	for (int i = 0; i < kats.size(); ++i)
	{
		Blowfish c;
		c.generateKeys(kats[i].key);
		std::vector<uint8_t> v = hexToVec(kats[i].plain);
		std::vector<uint8_t> expected = hexToVec(kats[i].cipher);
		c.encryptECB(&v[0], 8);
		snprintf(name, sizeof(name), "%s %02d: %s / %s", label, i + 1, kats[i].key, kats[i].plain);
		CHECK(compareVector(v, expected), name);
	}
}

std::vector<Kat> officialKats()
{
	std::vector<Kat> k;
	k.push_back(Kat{"0000000000000000", "0000000000000000", "4EF997456198DD78"});
	k.push_back(Kat{"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"});
	k.push_back(Kat{"3000000000000000", "1000000000000001", "7D856F9A613063F2"});
	k.push_back(Kat{"1111111111111111", "1111111111111111", "2466DD878B963C9D"});
	k.push_back(Kat{"0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"});
	k.push_back(Kat{"1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7"});
	k.push_back(Kat{"0000000000000000", "0000000000000000", "4EF997456198DD78"});
	k.push_back(Kat{"FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"});
	k.push_back(Kat{"7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"});
	k.push_back(Kat{"0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"});
	k.push_back(Kat{"07A1133E4A0B2686", "0248D43806F67172", "1730E5778BEA1DA4"});
	k.push_back(Kat{"3849674C2602319E", "51454B582DDF440A", "A25E7856CF2651EB"});
	k.push_back(Kat{"04B915BA43FEB5B6", "42FD443059577FA2", "353882B109CE8F1A"});
	k.push_back(Kat{"0113B970FD34F2CE", "059B5E0851CF143A", "48F4D0884C379918"});
	k.push_back(Kat{"0170F175468FB5E6", "0756D8E0774761D2", "432193B78951FC98"});
	k.push_back(Kat{"43297FAD38E373FE", "762514B829BF486A", "13F04154D69D1AE5"});
	k.push_back(Kat{"07A7137045DA2A16", "3BDD119049372802", "2EEDDA93FFD39C79"});
	k.push_back(Kat{"04689104C2FD3B2F", "26955F6835AF609A", "D887E0393C2DA6E3"});
	k.push_back(Kat{"37D06BB516CB7546", "164D5E404F275232", "5F99D04F5B163969"});
	k.push_back(Kat{"1F08260D1AC2465E", "6B056E18759F5CCA", "4A057A3B24D3977B"});
	k.push_back(Kat{"584023641ABA6176", "004BD6EF09176062", "452031C1E4FADA8E"});
	k.push_back(Kat{"025816164629B007", "480D39006EE762F2", "7555AE39F59B87BD"});
	k.push_back(Kat{"49793EBC79B3258F", "437540C8698F3CFA", "53C55F9CB49FC019"});
	k.push_back(Kat{"4FB05E1515AB73A7", "072D43A077075292", "7A8E7BFA937E89A3"});
	k.push_back(Kat{"49E95D6D4CA229BF", "02FE55778117F12A", "CF9C5D7A4986ADB5"});
	k.push_back(Kat{"018310DC409B26D6", "1D9D5C5018F728C2", "D1ABB290658BC778"});
	k.push_back(Kat{"1C587F1C13924FEF", "305532286D6F295A", "55CB3774D13EF201"});
	k.push_back(Kat{"0101010101010101", "0123456789ABCDEF", "FA34EC4847B268B2"});
	k.push_back(Kat{"1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "A790795108EA3CAE"});
	k.push_back(Kat{"E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "C39E072D9FAC631D"});
	k.push_back(Kat{"0000000000000000", "FFFFFFFFFFFFFFFF", "014933E0CDAFF6E4"});
	k.push_back(Kat{"FFFFFFFFFFFFFFFF", "0000000000000000", "F21E9A77B71C49BC"});
	k.push_back(Kat{"0123456789ABCDEF", "0000000000000000", "245946885754369A"});
	k.push_back(Kat{"FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "6B5C5A9C5D9E0A5A"});
	return k;
}

int main()
{
	printf("== Blowfish known-answer tests (official ECB vectors) ==\n");
	runKat(officialKats(), "official ecb");
	{
		Blowfish c;
		c.generateKeys("AABB09182736CCDD");
		std::vector<uint8_t> v({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36});
		c.encryptECB(&v[0], 8);
		CHECK(compareVector(v, std::vector<uint8_t>({0xc8, 0xfd, 0xca, 0xea, 0x64, 0xfa, 0x2c, 0x82})), "repo vector: key=AABB09182736CCDD -> c8fdcaea64fa2c82");
	}

	printf("== ECB round trip ==\n");
	{
		Blowfish c, d;
		c.generateKeys("0123456789abcdef");
		d.generateKeys("0123456789abcdef");
		std::vector<uint8_t> v, w;
		for (int i = 0; i < 24; ++i)
			v.push_back((uint8_t)(0xA5 + i));
		w = v;
		c.encryptECB(&v[0], 24);
		CHECK(!compareVector(v, w), "ecb ciphertext differs from plaintext");
		d.decryptECB(&v[0], 24);
		CHECK(compareVector(v, w), "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		Blowfish c, d;
		c.generateKeys("0123456789abcdef");
		d.generateKeys("0123456789abcdef");
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
		c.generateKeys("0123456789abcdef");
		d.generateKeys("0123456789abcdef");
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
		c.generateKeys("0123456789abcdef");
		d.generateKeys("0123456789abcdef");
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
		c.generateKeys("00112233445566778899aabbccddeeff");
		d.generateKeys("00112233445566778899aabbccddeeff");
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
		c.generateKeys("00112233445566778899aabbccddeeff");
		std::vector<uint8_t> pt(8, 0x7A);
		std::vector<uint8_t> iv(8, 0);
		std::vector<uint8_t> ct = c.encrypt(pt, iv);
		CHECK(ct.size() == 16, "block-aligned input gets a full padding block (PKCS#7)");
	}

	printf("== file API ==\n");
	{
		char path16[] = "/tmp/bf_test16.bin";
		Blowfish c;
		c.generateKeys("0123456789abcdef");
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
		c.generateKeys("0123456789abcdef");
		std::vector<uint8_t> orig({0xAA, 0xBB, 0xCC});
		writeFile(path3, orig);
		c.encrypt_File(path3);
		CHECK(readFile(path3).size() == 8, "short file padded to a full block by encrypt_File");
		CHECK(!compareVector(readFile(path3), orig), "short file changed by encrypt_File");
		c.decrypt_File(path3);
		CHECK(compareVector(readFile(path3), orig), "short file round trip after padding");
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}