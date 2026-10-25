#ifndef PADDING_HEADER
#define PADDING_HEADER

#include <stdint.h>
#include <vector>

enum class Padding { None, Zeros, PKCS7, ANSIX923, ISO78164 };

int missingFor(int len, int blockSize);

void pad(std::vector<uint8_t>& buf, int missing, Padding type);

/* Returns false when the padding is malformed and leaves buf untouched;
   returns true, with the padding removed, otherwise. Padding::None and
   Padding::Zeros remove nothing. */
bool unpad(std::vector<uint8_t>& buf, Padding type, int blockSize);

#endif
