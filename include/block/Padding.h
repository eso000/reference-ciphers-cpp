#ifndef PADDING_HEADER
#define PADDING_HEADER

#include <stdint.h>
#include <vector>

enum class Padding { None, Zeros, PKCS7, ANSIX923, ISO78164 };

int missingFor(int len, int blockSize);

void pad(std::vector<uint8_t>& buf, int missing, Padding type);

void unpad(std::vector<uint8_t>& buf, Padding type, int blockSize);

#endif
