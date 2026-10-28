#pragma once

#include <bit>
#include <cstdint>

#include "force_inline.h"

/* Bit and endian helpers shared by the cipher implementations. They are free
   functions, so the round helpers in each cipher's .cpp can use them without
   going through BlockCipher. They keep the always_inline binding that
   force_inline.h documents, because they sit in the hot inner loops. */
namespace block::detail {

FORCE_INLINE constexpr uint8_t byte0(uint32_t x) { return static_cast<uint8_t>(x >> 24); }
FORCE_INLINE constexpr uint8_t byte1(uint32_t x) { return static_cast<uint8_t>(x >> 16); }
FORCE_INLINE constexpr uint8_t byte2(uint32_t x) { return static_cast<uint8_t>(x >> 8); }
FORCE_INLINE constexpr uint8_t byte3(uint32_t x) { return static_cast<uint8_t>(x); }

FORCE_INLINE constexpr uint32_t rotl(uint32_t x, int n) { return std::rotl(x, n); }
FORCE_INLINE constexpr uint32_t rotr(uint32_t x, int n) { return std::rotr(x, n); }

FORCE_INLINE constexpr uint32_t load32_be(const uint8_t *p) {
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | uint32_t{p[3]};
}

FORCE_INLINE constexpr void store32_be(uint8_t *p, uint32_t w) {
    p[0] = byte0(w);
    p[1] = byte1(w);
    p[2] = byte2(w);
    p[3] = byte3(w);
}

FORCE_INLINE constexpr uint32_t load32_le(const uint8_t *p) {
    return uint32_t{p[0]} | (uint32_t{p[1]} << 8) | (uint32_t{p[2]} << 16) | (uint32_t{p[3]} << 24);
}

FORCE_INLINE constexpr void store32_le(uint8_t *p, uint32_t w) {
    p[0] = byte3(w);
    p[1] = byte2(w);
    p[2] = byte1(w);
    p[3] = byte0(w);
}

} // namespace block::detail
