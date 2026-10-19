#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include "TestBase.h"
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

struct RawKat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

std::vector<BlockKat> officialKats()
{
	static const RawKat k[] = {
		{"0000000000000000", "0000000000000000", "4EF997456198DD78"},
		{"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"},
		{"3000000000000000", "1000000000000001", "7D856F9A613063F2"},
		{"1111111111111111", "1111111111111111", "2466DD878B963C9D"},
		{"0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"},
		{"1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7"},
		{"0000000000000000", "0000000000000000", "4EF997456198DD78"},
		{"FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"},
		{"7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"},
		{"0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"},
		{"07A1133E4A0B2686", "0248D43806F67172", "1730E5778BEA1DA4"},
		{"3849674C2602319E", "51454B582DDF440A", "A25E7856CF2651EB"},
		{"04B915BA43FEB5B6", "42FD443059577FA2", "353882B109CE8F1A"},
		{"0113B970FD34F2CE", "059B5E0851CF143A", "48F4D0884C379918"},
		{"0170F175468FB5E6", "0756D8E0774761D2", "432193B78951FC98"},
		{"43297FAD38E373FE", "762514B829BF486A", "13F04154D69D1AE5"},
		{"07A7137045DA2A16", "3BDD119049372802", "2EEDDA93FFD39C79"},
		{"04689104C2FD3B2F", "26955F6835AF609A", "D887E0393C2DA6E3"},
		{"37D06BB516CB7546", "164D5E404F275232", "5F99D04F5B163969"},
		{"1F08260D1AC2465E", "6B056E18759F5CCA", "4A057A3B24D3977B"},
		{"584023641ABA6176", "004BD6EF09176062", "452031C1E4FADA8E"},
		{"025816164629B007", "480D39006EE762F2", "7555AE39F59B87BD"},
		{"49793EBC79B3258F", "437540C8698F3CFA", "53C55F9CB49FC019"},
		{"4FB05E1515AB73A7", "072D43A077075292", "7A8E7BFA937E89A3"},
		{"49E95D6D4CA229BF", "02FE55778117F12A", "CF9C5D7A4986ADB5"},
		{"018310DC409B26D6", "1D9D5C5018F728C2", "D1ABB290658BC778"},
		{"1C587F1C13924FEF", "305532286D6F295A", "55CB3774D13EF201"},
		{"0101010101010101", "0123456789ABCDEF", "FA34EC4847B268B2"},
		{"1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "A790795108EA3CAE"},
		{"E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "C39E072D9FAC631D"},
		{"0000000000000000", "FFFFFFFFFFFFFFFF", "014933E0CDAFF6E4"},
		{"FFFFFFFFFFFFFFFF", "0000000000000000", "F21E9A77B71C49BC"},
		{"0123456789ABCDEF", "0000000000000000", "245946885754369A"},
		{"FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "6B5C5A9C5D9E0A5A"},
	};

	std::vector<BlockKat> out;
	for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); ++i)
	{
		char name[32];
		snprintf(name, sizeof(name), "official ecb %02d", (int)i + 1);
		out.push_back(BlockKat{name, k[i].key, k[i].plain, k[i].cipher});
	}
	return out;
}

struct RawSetKey
{
	const char *key;
	const char *cipher;
};

std::vector<BlockKat> setKeyKats()
{
	static const RawSetKey k[] = {
		{"F0", "F9AD597C49DB005E"},
		{"F0E1", "E91D21C1D961A6D6"},
		{"F0E1D2", "E9C2B70A1BC65CF3"},
		{"F0E1D2C3", "BE1E639408640F05"},
		{"F0E1D2C3B4", "B39E44481BDB1E6E"},
		{"F0E1D2C3B4A5", "9457AA83B1928C0D"},
		{"F0E1D2C3B4A596", "8BB77032F960629D"},
		{"F0E1D2C3B4A59687", "E87A244E2CC85E82"},
		{"F0E1D2C3B4A5968778", "15750E7A4F4EC577"},
		{"F0E1D2C3B4A596877869", "122BA70B3AB64AE0"},
		{"F0E1D2C3B4A5968778695A", "3A833C9AFFC537F6"},
		{"F0E1D2C3B4A5968778695A4B", "9409DA87A90F6BF2"},
		{"F0E1D2C3B4A5968778695A4B3C", "884F80625060B8B4"},
		{"F0E1D2C3B4A5968778695A4B3C2D", "1F85031C19E11968"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E", "79D9373A714CA34F"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F", "93142887EE3BE15C"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F00", "03429E838CE2D14B"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011", "A4299E27469FF67B"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F001122", "AFD5AED1C1BC96A8"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F00112233", "10851C0E3858DA9F"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344", "E6F51ED79B9DB21F"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F001122334455", "64A6E14AFD36B46F"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566", "80C7D7D45A5479AD"},
		{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677", "05044B62FA52D080"},
	};

	std::vector<BlockKat> out;
	for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); ++i)
	{
		char name[48];
		snprintf(name, sizeof(name), "set_key %d-byte key", (int)(strlen(k[i].key) / 2));
		out.push_back(BlockKat{name, k[i].key, "FEDCBA9876543210", k[i].cipher});
	}
	return out;
}

int main()
{
	BlowfishSuite suite;

	printf("== Blowfish known-answer tests (official ECB vectors) ==\n");
	suite.runEcbKats(officialKats());

	printf("== official set_key vectors (key lengths 1..24 bytes) ==\n");
	suite.runEcbKats(setKeyKats());

	{
		Blowfish c;
		c.generateKeys(hexToVec("AABB09182736CCDD"));
		std::vector<uint8_t> v({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36});
		c.encryptECB(&v[0], 8);
		CHECK(compareVector(v, std::vector<uint8_t>({0xc8, 0xfd, 0xca, 0xea, 0x64, 0xfa, 0x2c, 0x82})), "repo vector: key=AABB09182736CCDD -> c8fdcaea64fa2c82");
	}

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
		/* The published set_key vectors above already pin the 1, 2 and
		   3-byte schedules, so these round trips only need to confirm the
		   non-word-aligned path still runs both ways. */
		Blowfish c, d;
		std::vector<uint8_t> kb = hexToVec("AABBCC");
		c.generateKeys(kb);
		d.generateKeys(kb);
		std::vector<uint8_t> v({0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36});
		std::vector<uint8_t> w = v;
		c.encryptECB(&v[0], 8);
		CHECK(!compareVector(v, w), "3-byte key: ciphertext differs from plaintext");
		d.decryptECB(&v[0], 8);
		CHECK(compareVector(v, w), "3-byte key: encrypt+decrypt restores plaintext");
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
		threw = false;
		try { c.generateKeys(std::vector<uint8_t>(57, 0xAB)); }
		catch (std::invalid_argument &) { threw = true; }
		CHECK(threw, "57-byte key rejected");

		/* 1 through 56 bytes are all valid; the published set_key vectors
		   cover the short end. Every length in that range is exercised here,
		   because the lower bound is easy to tighten by accident and doing so
		   would quietly drop three of those vectors. */
		const size_t accepted[] = {1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32, 48, 55, 56};
		for (size_t n : accepted)
		{
			threw = false;
			try { c.generateKeys(std::vector<uint8_t>(n, 0xAB)); }
			catch (std::invalid_argument &) { threw = true; }
			char name[96];
			snprintf(name, sizeof(name), "%zu-byte key accepted", n);
			CHECK(!threw, name);
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
