#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace block {

enum class Padding { None, Zeros, PKCS7, ANSIX923, ISO78164 };

size_t missingFor(size_t len, size_t blockSize);

void pad(std::vector<uint8_t> &buf, size_t missing, Padding type);

/* Returns false when the padding is malformed and leaves buf untouched;
   returns true, with the padding removed, otherwise. Padding::None and
   Padding::Zeros remove nothing. */
bool unpad(std::vector<uint8_t> &buf, Padding type, size_t blockSize);

} // namespace block
