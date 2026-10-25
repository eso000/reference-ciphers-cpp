#include <vector>
#include <string>
#include <stdexcept>

#include "TestBase.h"
#include "block/AES.h"
#include "block/Blowfish.h"
#include "block/Twofish.h"
#include "block/DES.h"
#include "block/Serpent.h"

using namespace block;

template <typename F>
static bool throwsInvalidArgument(F fn)
{
	try
	{
		fn();
	}
	catch (const std::invalid_argument &)
	{
		return true;
	}
	catch (...)
	{
		return false;
	}
	return false;
}

template <typename Ex, typename F>
static bool throwsAs(F fn)
{
	try
	{
		fn();
	}
	catch (const Ex &)
	{
		return true;
	}
	catch (...)
	{
		return false;
	}
	return false;
}

static std::vector<uint8_t> ivFor(int bs)
{
	std::vector<uint8_t> iv;
	for (int i = 0; i < bs; ++i)
		iv.push_back((uint8_t)(0x11 * (i + 1)));
	return iv;
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

			std::vector<uint8_t> useIV = (modes[m] == BlockMode::ECB)
				? std::vector<uint8_t>() : iv;
			std::vector<uint8_t> ct = c.encryptMode(pt, modes[m], pads[p], useIV);
			std::vector<uint8_t> rt = d.decryptMode(ct, modes[m], pads[p], useIV);
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

	/* Zeros fills only up to the next block boundary, so empty and aligned
	   messages receive no extra block. */
	const BlockMode blockModes[] = {BlockMode::ECB, BlockMode::CBC, BlockMode::PCBC};
	const char *blockNames[] = {"ECB", "CBC", "PCBC"};
	std::vector<uint8_t> empty;
	std::vector<uint8_t> aligned(bs, 0x41);
	std::vector<uint8_t> shortPt = {'h', 'e', 'l', 'l', 'o'};

	for (int m = 0; m < 3; ++m)
	{
		std::vector<uint8_t> useIV = (blockModes[m] == BlockMode::ECB)
			? std::vector<uint8_t>() : iv;

		std::vector<uint8_t> emptyCt = c.encryptMode(empty, blockModes[m], Padding::Zeros, useIV);
		std::vector<uint8_t> emptyRt = d.decryptMode(empty, blockModes[m], Padding::Zeros, useIV);
		snprintf(label, sizeof(label), "%s %s + Zeros leaves empty input empty",
		         name, blockNames[m]);
		CHECK(emptyCt.empty() && emptyRt.empty(), label);

		std::vector<uint8_t> alignedCt = c.encryptMode(aligned, blockModes[m],
		                                               Padding::Zeros, useIV);
		std::vector<uint8_t> alignedRt = d.decryptMode(alignedCt, blockModes[m],
		                                               Padding::Zeros, useIV);
		snprintf(label, sizeof(label), "%s %s + Zeros adds no block to aligned input",
		         name, blockNames[m]);
		CHECK(alignedCt.size() == aligned.size() && compareVector(alignedRt, aligned), label);

		std::vector<uint8_t> shortCt = c.encryptMode(shortPt, blockModes[m],
		                                             Padding::Zeros, useIV);
		std::vector<uint8_t> shortRt = d.decryptMode(shortCt, blockModes[m],
		                                             Padding::Zeros, useIV);
		int shortPrefix = shortRt.size() >= shortPt.size()
			&& memcmp(&shortRt[0], &shortPt[0], shortPt.size()) == 0;
		int shortZeros = 1;
		for (size_t i = shortPt.size(); i < shortRt.size(); ++i)
			if (shortRt[i] != 0)
				shortZeros = 0;
		snprintf(label, sizeof(label), "%s %s + Zeros pads a short message to one block",
		         name, blockNames[m]);
		CHECK(shortCt.size() == (size_t) bs && shortPrefix && shortZeros, label);
	}
}

/* The regression this suite was missing: a keystream mode used to act only on
   whole blocks, so a five-byte message came back unchanged. A round-trip test
   cannot see that -- encryption and decryption were both the identity -- so
   each check below also compares the ciphertext with the plaintext. */
static void runStreamTail(const char *name, BlockCipher& c, BlockCipher& d)
{
	int bs = c.blockSize();
	std::vector<uint8_t> iv = ivFor(bs);

	const BlockMode modes[] = {BlockMode::CFB, BlockMode::OFB, BlockMode::CTR};
	const char *modeNames[] = {"CFB", "OFB", "CTR"};
	char label[160];

	for (int m = 0; m < 3; ++m)
	{
		std::vector<uint8_t> pt = {'h', 'e', 'l', 'l', 'o'};
		std::vector<uint8_t> ct = c.encryptMode(pt, modes[m], Padding::None, iv);
		std::vector<uint8_t> rt = d.decryptMode(ct, modes[m], Padding::None, iv);

		snprintf(label, sizeof(label), "%s %s 5-byte ciphertext keeps plaintext length",
		         name, modeNames[m]);
		CHECK(ct.size() == pt.size(), label);

		snprintf(label, sizeof(label), "%s %s 5-byte ciphertext is not the plaintext",
		         name, modeNames[m]);
		CHECK(!compareVector(ct, pt), label);

		snprintf(label, sizeof(label), "%s %s 5-byte round trip", name, modeNames[m]);
		CHECK(compareVector(rt, pt), label);
	}

	for (int len = 1; len <= 3 * bs + 1; ++len)
	{
		std::vector<uint8_t> pt;
		for (int i = 0; i < len; ++i)
			pt.push_back((uint8_t)(0x40 + i));

		for (int m = 0; m < 3; ++m)
		{
			std::vector<uint8_t> ct = c.encryptMode(pt, modes[m], Padding::None, iv);
			std::vector<uint8_t> rt = d.decryptMode(ct, modes[m], Padding::None, iv);

			snprintf(label, sizeof(label), "%s %s length %d round trip",
			         name, modeNames[m], len);
			CHECK(ct.size() == pt.size() && compareVector(rt, pt) && !compareVector(ct, pt),
			      label);
		}
	}

	/* The keystream modes ignore the padding argument, as the C and Python
	   siblings do, so the ciphertext must not depend on it. */
	std::vector<uint8_t> pt = hexToVec("00112233445566778899aabbccddeeff");
	for (int m = 0; m < 3; ++m)
	{
		std::vector<uint8_t> none = c.encryptMode(pt, modes[m], Padding::None, iv);
		std::vector<uint8_t> pkcs = c.encryptMode(pt, modes[m], Padding::PKCS7, iv);
		std::vector<uint8_t> zeros = c.encryptMode(pt, modes[m], Padding::Zeros, iv);

		snprintf(label, sizeof(label), "%s %s ignores the padding argument",
		         name, modeNames[m]);
		CHECK(none.size() == pt.size() && compareVector(none, pkcs) && compareVector(none, zeros),
		      label);
	}
}

/* Craft a CTR ciphertext that decrypts to fifteen zero bytes and 0x01, then
   check that decrypting it with a padding argument leaves all sixteen bytes. */
static void runStreamPaddingNotStripped(BlockCipher& c, BlockCipher& d)
{
	int bs = c.blockSize();
	std::vector<uint8_t> iv = ivFor(bs);
	std::vector<uint8_t> zeros(bs, 0);
	std::vector<uint8_t> ct = c.encryptMode(zeros, BlockMode::CTR, Padding::None, iv);
	ct[bs - 1] ^= 0x01;

	std::vector<uint8_t> rt = d.decryptMode(ct, BlockMode::CTR, Padding::PKCS7, iv);

	std::vector<uint8_t> want(bs, 0);
	want[bs - 1] = 0x01;
	CHECK(compareVector(rt, want), "stream decrypt does not strip a padding-looking tail");
}

static void runModeErrors(const char *name, BlockCipher& c)
{
	int bs = c.blockSize();
	std::vector<uint8_t> iv = ivFor(bs);
	std::vector<uint8_t> shortIV(bs - 1, 0x33);
	std::vector<uint8_t> longIV(bs + 1, 0x33);
	std::vector<uint8_t> pt5 = {'h', 'e', 'l', 'l', 'o'};
	std::vector<uint8_t> pt16(bs, 0x41);
	char label[160];

	const BlockMode blockModes[] = {BlockMode::ECB, BlockMode::CBC, BlockMode::PCBC};
	const char *blockNames[] = {"ECB", "CBC", "PCBC"};

	for (int m = 0; m < 3; ++m)
	{
		std::vector<uint8_t> useIV = (blockModes[m] == BlockMode::ECB)
			? std::vector<uint8_t>() : iv;

		snprintf(label, sizeof(label), "%s %s Padding::None rejects an unaligned message",
		         name, blockNames[m]);
		CHECK(throwsInvalidArgument([&] {
			c.encryptMode(pt5, blockModes[m], Padding::None, useIV);
		}), label);

		snprintf(label, sizeof(label), "%s %s Padding::None rejects an unaligned ciphertext",
		         name, blockNames[m]);
		CHECK(throwsInvalidArgument([&] {
			c.decryptMode(pt5, blockModes[m], Padding::None, useIV);
		}), label);

		/* An empty ciphertext has no padding block, so every strict scheme
		   must reject it instead of returning an empty plaintext. */
		const Padding strict[] = {Padding::PKCS7, Padding::ANSIX923, Padding::ISO78164};
		const char *strictNames[] = {"PKCS7", "ANSIX923", "ISO78164"};
		for (int p = 0; p < 3; ++p)
		{
			std::vector<uint8_t> empty;
			snprintf(label, sizeof(label),
			         "%s %s + %s rejects an empty ciphertext",
			         name, blockNames[m], strictNames[p]);
			CHECK(throwsInvalidArgument([&] {
				c.decryptMode(empty, blockModes[m], strict[p], useIV);
			}), label);
		}
	}

	snprintf(label, sizeof(label), "%s CBC rejects a short IV", name);
	CHECK(throwsInvalidArgument([&] {
		c.encryptMode(pt16, BlockMode::CBC, Padding::PKCS7, shortIV);
	}), label);

	snprintf(label, sizeof(label), "%s CBC rejects a long IV", name);
	CHECK(throwsInvalidArgument([&] {
		c.encryptMode(pt16, BlockMode::CBC, Padding::PKCS7, longIV);
	}), label);

	snprintf(label, sizeof(label), "%s CBC rejects a missing IV", name);
	CHECK(throwsInvalidArgument([&] {
		c.encryptMode(pt16, BlockMode::CBC, Padding::PKCS7);
	}), label);

	snprintf(label, sizeof(label), "%s ECB rejects an IV", name);
	CHECK(throwsInvalidArgument([&] {
		c.encryptMode(pt16, BlockMode::ECB, Padding::PKCS7, iv);
	}), label);

	snprintf(label, sizeof(label), "%s CFB rejects a short IV", name);
	CHECK(throwsInvalidArgument([&] {
		c.encryptMode(pt16, BlockMode::CFB, Padding::None, shortIV);
	}), label);

	/* A ciphertext that decrypts to a bad PKCS7 tail must be an error, not a
	   buffer of still-padded data. */
	std::vector<uint8_t> bad = c.encryptMode(std::vector<uint8_t>(bs, 0),
	                                         BlockMode::CBC, Padding::None, iv);
	snprintf(label, sizeof(label), "%s malformed PKCS7 padding is rejected", name);
	CHECK(throwsInvalidArgument([&] {
		c.decryptMode(bad, BlockMode::CBC, Padding::PKCS7, iv);
	}), label);
}

/* Every operation that consumes the key schedule must refuse a cipher that
   has no keys. A failed generateKeys() also leaves the cipher unkeyed rather
   than exposing a partial or stale schedule. */
template <typename BadKey, typename GoodKey>
static void runKeyGuard(const char *name, BlockCipher &c, BadKey badKey, GoodKey goodKey)
{
	int bs = c.blockSize();
	char label[160];
	std::vector<uint8_t> block(bs, 0x5a);
	std::vector<uint8_t> pt(bs, 0x41);
	char path[] = "/tmp/opencode/keyguard-unused";

	snprintf(label, sizeof(label), "%s encryptBlock without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] { c.encryptBlock(&block[0]); }), label);

	snprintf(label, sizeof(label), "%s decryptBlock without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] { c.decryptBlock(&block[0]); }), label);

	snprintf(label, sizeof(label), "%s encryptECB without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] { c.encryptECB(std::span<uint8_t>(block).first(bs)); }), label);

	snprintf(label, sizeof(label), "%s decryptECB without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] { c.decryptECB(std::span<uint8_t>(block).first(bs)); }), label);

	snprintf(label, sizeof(label), "%s encryptMode without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] {
		c.encryptMode(pt, BlockMode::ECB, Padding::PKCS7);
	}), label);

	snprintf(label, sizeof(label), "%s decryptMode without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] {
		c.decryptMode(std::vector<uint8_t>(), BlockMode::ECB, Padding::None);
	}), label);

	snprintf(label, sizeof(label), "%s encrypt_File without generateKeys throws", name);
	CHECK(throwsAs<std::logic_error>([&] { c.encrypt_File(path); }), label);

	snprintf(label, sizeof(label), "%s rejects an invalid key", name);
	CHECK(throwsInvalidArgument(badKey), label);

	snprintf(label, sizeof(label), "%s stays unusable after a failed generateKeys", name);
	CHECK(throwsAs<std::logic_error>([&] {
		c.encryptMode(pt, BlockMode::ECB, Padding::PKCS7);
	}), label);

	goodKey();
	std::vector<uint8_t> ct = c.encryptMode(pt, BlockMode::ECB, Padding::PKCS7);
	std::vector<uint8_t> rt = c.decryptMode(ct, BlockMode::ECB, Padding::PKCS7);
	snprintf(label, sizeof(label), "%s works after a successful generateKeys", name);
	CHECK(ct.size() == pt.size() + (size_t) bs && compareVector(rt, pt), label);
}

/* NIST SP 800-38A Appendix F.5 for AES-128: CFB128, OFB and CTR. */
static void runAesModeKats()
{
	const char *ptHex =
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
	const char *key = "2b7e151628aed2a6abf7158809cf4f3c";
	const char *cfbIV = "000102030405060708090a0b0c0d0e0f";
	const char *ofbIV = "000102030405060708090a0b0c0d0e0f";
	const char *ctrIV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

	struct Kat
	{
		BlockMode mode;
		const char *name;
		const char *iv;
		const char *ct;
	};
	const Kat kats[] = {
		{BlockMode::CFB, "SP 800-38A F.5.3 CFB128", cfbIV,
		 "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
		 "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"},
		{BlockMode::OFB, "SP 800-38A F.5.4 OFB", ofbIV,
		 "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
		 "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"},
		{BlockMode::CTR, "SP 800-38A F.5.5 CTR", ctrIV,
		 "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
		 "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"},
	};

	AES e, d;
	e.generateKeys(key);
	d.generateKeys(key);
	std::vector<uint8_t> pt = hexToVec(ptHex);

	for (const Kat &k : kats)
	{
		std::vector<uint8_t> iv = hexToVec(k.iv);
		std::vector<uint8_t> want = hexToVec(k.ct);
		std::vector<uint8_t> got = e.encryptMode(pt, k.mode, Padding::None, iv);
		char label[128];
		snprintf(label, sizeof(label), "AES %s encrypt", k.name);
		CHECK(compareVector(got, want), label);

		std::vector<uint8_t> rt = d.decryptMode(want, k.mode, Padding::None, iv);
		snprintf(label, sizeof(label), "AES %s decrypt", k.name);
		CHECK(compareVector(rt, pt), label);
	}

	/* 71 bytes is eight full blocks and a seven-byte tail, so these pin the
	   short-final-block path against an external answer rather than only
	   against its own inverse. The values match the C sibling's TailKat and
	   OpenSSL 3.5.9. */
	const Kat tails[] = {
		{BlockMode::CFB, "CFB128 71-byte tail", cfbIV,
		 "10bf258fdd2874f192407da2d7e2a22f8924f2a21fc0f272145dedd5a1bce059"
		 "217686b9dbf031f8974fade25a6f89dd02b8a1766037d6bf56e5f81650e7b6250"
		 "48feb926fe3e4"},
		{BlockMode::OFB, "OFB 71-byte tail", ofbIV,
		 "10bf258fdd2874f192407da2d7e2a22f89f588895cc775c833d2672ddcbc082b"
		 "c7e97b3b5b666e80ced65cda5407d14cb6a2331e5d632a18b3f72bd95bc7e731e"
		 "a1b1861bf1bc1"},
		{BlockMode::CTR, "CTR 71-byte tail", ctrIV,
		 "accd9d30dc253af7ba9b5c3ea6d3efab667a2e6f3326073440f92d8ca00d2df1"
		 "0a4da11b1cec5128d6dda2707bd7022b98ed4bec8484eeb1ac734ba06911d5813"
		 "08cc57b900f17"},
	};

	std::vector<uint8_t> tailPt;
	for (int i = 0; i < 71; ++i)
		tailPt.push_back((uint8_t)(0x40 + i));

	for (const Kat &k : tails)
	{
		std::vector<uint8_t> iv = hexToVec(k.iv);
		std::vector<uint8_t> want = hexToVec(k.ct);
		std::vector<uint8_t> got = e.encryptMode(tailPt, k.mode, Padding::None, iv);
		char label[128];
		snprintf(label, sizeof(label), "AES %s encrypt", k.name);
		CHECK(compareVector(got, want), label);

		std::vector<uint8_t> rt = d.decryptMode(want, k.mode, Padding::None, iv);
		snprintf(label, sizeof(label), "AES %s decrypt", k.name);
		CHECK(compareVector(rt, tailPt), label);
	}
}

int main()
{
	printf("== modes, paddings and stream-mode partial blocks ==\n");

	{
		AES c, d;
		c.generateKeys("000102030405060708090a0b0c0d0e0f");
		d.generateKeys("000102030405060708090a0b0c0d0e0f");
		runCipher("AES", c, d);
		runStreamTail("AES", c, d);
		runStreamPaddingNotStripped(c, d);
		runModeErrors("AES", c);
	}
	{
		Blowfish c, d;
		c.generateKeys(hexToVec("0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef"));
		runCipher("Blowfish", c, d);
		runStreamTail("Blowfish", c, d);
		runStreamPaddingNotStripped(c, d);
		runModeErrors("Blowfish", c);
	}
	{
		Twofish c, d;
		c.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		d.generateKeys(hexToVec("0123456789abcdef0123456789abcdef"));
		runCipher("Twofish", c, d);
		runStreamTail("Twofish", c, d);
		runStreamPaddingNotStripped(c, d);
		runModeErrors("Twofish", c);
	}
	{
		DES c, d;
		c.generateKeys("133457799BBCDFF1");
		d.generateKeys("133457799BBCDFF1");
		runCipher("DES", c, d);
		runStreamTail("DES", c, d);
		runStreamPaddingNotStripped(c, d);
		runModeErrors("DES", c);
	}
	{
		Serpent c, d;
		c.generateKeys("000102030405060708090a0b0c0d0e0f");
		d.generateKeys("000102030405060708090a0b0c0d0e0f");
		runCipher("Serpent", c, d);
		runStreamTail("Serpent", c, d);
		runStreamPaddingNotStripped(c, d);
		runModeErrors("Serpent", c);
	}

	printf("== key schedule guard ==\n");
	{
		AES u;
		runKeyGuard("AES", u,
			[&] { u.generateKeys("00"); },
			[&] { u.generateKeys("000102030405060708090a0b0c0d0e0f"); });
	}
	{
		Blowfish u;
		runKeyGuard("Blowfish", u,
			[&] { u.generateKeys(std::vector<uint8_t>()); },
			[&] { u.generateKeys(hexToVec("0123456789abcdef")); });
	}
	{
		Twofish u;
		runKeyGuard("Twofish", u,
			[&] { u.generateKeys(std::vector<uint8_t>()); },
			[&] { u.generateKeys(hexToVec("0123456789abcdef0123456789abcdef")); });
	}
	{
		DES u;
		runKeyGuard("DES", u,
			[&] { u.generateKeys("00"); },
			[&] { u.generateKeys("133457799BBCDFF1"); });
	}
	{
		Serpent u;
		runKeyGuard("Serpent", u,
			[&] { u.generateKeys(""); },
			[&] { u.generateKeys("000102030405060708090a0b0c0d0e0f"); });
	}

	printf("== NIST SP 800-38A keystream-mode known answers ==\n");
	runAesModeKats();

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
