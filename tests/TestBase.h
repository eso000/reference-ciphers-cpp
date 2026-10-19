#ifndef TESTBASE_HEADER
#define TESTBASE_HEADER

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "block/BlockCipher.h"

/* Shared test scaffolding. This mirrors the Python suite's
   tests/cipher_test_base.py: one place for the check/report harness and the
   generic known-answer and round-trip runners, so each cipher file only
   carries what is actually specific to that cipher. */

extern int g_fails;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

std::vector<uint8_t> hexToVec(const char *hex);

bool compareVector(const std::vector<uint8_t> &v, const std::vector<uint8_t> &w);

void printVec(const std::vector<uint8_t> &v);

/* One ECB known-answer vector: a whole number of blocks. */
struct BlockKat
{
	std::string name;
	const char *key;
	const char *plain;
	const char *cipher;
};

/* Base for the per-cipher suites. A subclass says how to build and key its
   cipher (makeKeyed, the equivalent of Python's make_cipher) and inherits the
   generic runners. Only the base interface is used, so the runners work for
   every cipher through the polymorphic BlockCipher. */
class CipherTestBase
{
public:
	virtual ~CipherTestBase() {}

	/* Build a cipher of this suite's type, keyed from a hex string. */
	virtual std::unique_ptr<BlockCipher> makeKeyed(const char *keyHex) const = 0;

	/* Every vector encrypts to its expected ciphertext. */
	void runEcbKats(const std::vector<BlockKat> &kats);

	/* Every vector decrypts back to its expected plaintext. */
	void runEcbKatsDec(const std::vector<BlockKat> &kats);

	/* A multi-block ECB plaintext round trips, and the ciphertext differs
	   from the plaintext. */
	void runEcbRoundTrip(const char *keyHex, int len, const char *label);

	/* Print the summary line and return a process exit code. */
	int report();
};

#endif
