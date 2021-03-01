/*
 * Copyright 2021 Assured Information Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef PORTABLE_ENDIAN_H__
#define PORTABLE_ENDIAN_H__

#include <cstdint>
#include <type_traits>

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)

#include <endian.h>

#elif defined(__APPLE__)

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN

#elif defined(__OpenBSD__)

#include <sys/endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#include <sys/endian.h>

#define be16toh(x) betoh16(x)
#define le16toh(x) letoh16(x)

#define be32toh(x) betoh32(x)
#define le32toh(x) letoh32(x)

#define be64toh(x) betoh64(x)
#define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)

#include <windows.h>

#if BYTE_ORDER == LITTLE_ENDIAN

#if defined(_MSC_VER)
#include <stdlib.h>
#define htobe16(x) _byteswap_ushort(x)
#define htole16(x) (x)
#define be16toh(x) _byteswap_ushort(x)
#define le16toh(x) (x)

#define htobe32(x) _byteswap_ulong(x)
#define htole32(x) (x)
#define be32toh(x) _byteswap_ulong(x)
#define le32toh(x) (x)

#define htobe64(x) _byteswap_uint64(x)
#define htole64(x) (x)
#define be64toh(x) _byteswap_uint64(x)
#define le64toh(x) (x)

#elif defined(__GNUC__) || defined(__clang__)

#define htobe16(x) __builtin_bswap16(x)
#define htole16(x) (x)
#define be16toh(x) __builtin_bswap16(x)
#define le16toh(x) (x)

#define htobe32(x) __builtin_bswap32(x)
#define htole32(x) (x)
#define be32toh(x) __builtin_bswap32(x)
#define le32toh(x) (x)

#define htobe64(x) __builtin_bswap64(x)
#define htole64(x) (x)
#define be64toh(x) __builtin_bswap64(x)
#define le64toh(x) (x)
#else
#error platform not supported
#endif

#else

#error byte order not supported

#endif

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN

#else

#error platform not supported

#endif

template <typename T>
inline T betoh(T src) {
    // This is for enum classes
    // We get the raw type of the enum, cast to that, convert endianness, and cast back to the enum.
    using raw_type = std::underlying_type_t<T>;
    return static_cast<T>(betoh<raw_type>(static_cast<raw_type>(src)));
}
template <typename T>
inline T htobe(T src) {
    // This is for enum classes
    // We get the raw type of the enum, cast to that, convert endianness, and cast back to the enum.
    using raw_type = std::underlying_type_t<T>;
    return static_cast<T>(htobe<raw_type>(static_cast<raw_type>(src)));
}

template <>
inline int16_t betoh(int16_t src) {
    return be16toh(src);
}
template <>
inline uint16_t betoh(uint16_t src) {
    return be16toh(src);
}
template <>
inline int32_t betoh(int32_t src) {
    return be32toh(src);
}
template <>
inline uint32_t betoh(uint32_t src) {
    return be32toh(src);
}
template <>
inline int64_t betoh(int64_t src) {
    return be64toh(src);
}
template <>
inline uint64_t betoh(uint64_t src) {
    return be64toh(src);
}

template <>
inline int16_t htobe(int16_t src) {
    return htobe16(src);
}
template <>
inline uint16_t htobe(uint16_t src) {
    return htobe16(src);
}
template <>
inline int32_t htobe(int32_t src) {
    return htobe32(src);
}
template <>
inline uint32_t htobe(uint32_t src) {
    return htobe32(src);
}
template <>
inline int64_t htobe(int64_t src) {
    return htobe64(src);
}
template <>
inline uint64_t htobe(uint64_t src) {
    return htobe64(src);
}

template <typename T>
inline T letoh(T src) {
    // This is for enum classes
    // We get the raw type of the enum, cast to that, convert endianness, and cast back to the enum.
    using raw_type = std::underlying_type_t<T>;
    return static_cast<T>(letoh<raw_type>(static_cast<raw_type>(src)));
}
template <typename T>
inline T htole(T src) {
    // This is for enum classes
    // We get the raw type of the enum, cast to that, convert endianness, and cast back to the enum.
    using raw_type = std::underlying_type_t<T>;
    return static_cast<T>(htole<raw_type>(static_cast<raw_type>(src)));
}

template <>
inline int16_t letoh(int16_t src) {
    return le16toh(src);
}
template <>
inline uint16_t letoh(uint16_t src) {
    return le16toh(src);
}
template <>
inline int32_t letoh(int32_t src) {
    return le32toh(src);
}
template <>
inline uint32_t letoh(uint32_t src) {
    return le32toh(src);
}
template <>
inline int64_t letoh(int64_t src) {
    return le64toh(src);
}
template <>
inline uint64_t letoh(uint64_t src) {
    return le64toh(src);
}

template <>
inline int16_t htole(int16_t src) {
    return htole16(src);
}
template <>
inline uint16_t htole(uint16_t src) {
    return htole16(src);
}
template <>
inline int32_t htole(int32_t src) {
    return htole32(src);
}
template <>
inline uint32_t htole(uint32_t src) {
    return htole32(src);
}
template <>
inline int64_t htole(int64_t src) {
    return htole64(src);
}
template <>
inline uint64_t htole(uint64_t src) {
    return htole64(src);
}

template <typename T>
class le_type {
  public:
    le_type() = default;
    inline void operator=(T src) { value = htole(src); }
    inline operator T() const { return letoh(value); }

  private:
    T value;
};

using le_int16_t = le_type<int16_t>;
using le_uint16_t = le_type<uint16_t>;
using le_int32_t = le_type<int32_t>;
using le_uint32_t = le_type<uint32_t>;
using le_int64_t = le_type<int64_t>;
using le_uint64_t = le_type<uint64_t>;

template <typename T>
class be_type {
  public:
    be_type() = default;
    inline void operator=(T src) { value = htobe(src); }
    inline operator T() const { return betoh(value); }

  private:
    T value;
};

using be_int16_t = be_type<int16_t>;
using be_uint16_t = be_type<uint16_t>;
using be_int32_t = be_type<int32_t>;
using be_uint32_t = be_type<uint32_t>;
using be_int64_t = be_type<int64_t>;
using be_uint64_t = be_type<uint64_t>;

#endif