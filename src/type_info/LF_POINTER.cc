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
#include "type_info/LF_POINTER.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

namespace mspdb {

#pragma pack(push, 1)

struct lfPointer {
    le_uint32_t underlying_type;
    le_uint32_t attr;
    /*
        union {
            struct {
                le_uint32_t pmclass;
                le_uint16_t pmenum;
            };
            uint16_t bseg;
            // char sym[];
            struct {
                le_uint32_t index;
                //char name[];
            };
        };
    */
};

#pragma pack(pop)

class LF_POINTER::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    lfPointer entry;
};

const LF_TYPE& LF_POINTER::underlying_type() const {
    return pImpl->tpi.type(pImpl->entry.underlying_type);
}
uint32_t LF_POINTER::pointer_attributes() const { return pImpl->entry.attr; }

CV_PointerType LF_POINTER::pointer_type() const {
    static const uint16_t PTR_TYPE_MASK = 0x1F;
    static const uint16_t PTR_TYPE_SHIFT = 0x0;

    return static_cast<CV_PointerType>((pImpl->entry.attr & PTR_TYPE_MASK) >> PTR_TYPE_SHIFT);
}
CV_PointerMode LF_POINTER::pointer_mode() const {
    static const uint16_t PTR_MODE_MASK = 0xE0;
    static const uint16_t PTR_MODE_SHIFT = 0x5;

    return static_cast<CV_PointerMode>((pImpl->entry.attr & PTR_MODE_MASK) >> PTR_MODE_SHIFT);
}
bool LF_POINTER::isflat32() const {
    static const uint16_t ISFLAT32_MASK = 0x100;
    return pImpl->entry.attr & ISFLAT32_MASK;
}
bool LF_POINTER::isvolatile() const {
    static const uint16_t ISVOLATILE_MASK = 0x200;
    return pImpl->entry.attr & ISVOLATILE_MASK;
}
bool LF_POINTER::isconst() const {
    static const uint16_t ISCONST_MASK = 0x400;
    return pImpl->entry.attr & ISCONST_MASK;
}
bool LF_POINTER::isunaligned() const {
    static const uint16_t ISUNALIGNED_MASK = 0x800;
    return pImpl->entry.attr & ISUNALIGNED_MASK;
}
bool LF_POINTER::isrestrict() const {
    static const uint16_t ISRESTRICT_MASK = 0x1000;
    return pImpl->entry.attr & ISRESTRICT_MASK;
}
uint16_t LF_POINTER::size() const {
    static const uint32_t SIZE_MASK = 0x7E000;
    static const uint16_t SIZE_SHIFT = 0xD;
    return (pImpl->entry.attr & SIZE_MASK) >> SIZE_SHIFT;
}
bool LF_POINTER::ismocom() const {
    static const uint32_t ISMOCOM_MASK = 0x80000;
    return pImpl->entry.attr & ISMOCOM_MASK;
}
bool LF_POINTER::islref() const {
    static const uint32_t ISLREF_MASK = 0x100000;
    return pImpl->entry.attr & ISLREF_MASK;
}
bool LF_POINTER::isrref() const {
    static const uint32_t ISRREF_MASK = 0x200000;
    return pImpl->entry.attr & ISRREF_MASK;
}

LF_POINTER::LF_POINTER(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {

    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfPointer))) {
        throw pdb_exception("Buffer too small for LF_POINTER");
    }
    pImpl->entry = *reinterpret_cast<const lfPointer*>(buffer);
}

LF_POINTER::~LF_POINTER() = default;

} /* namespace mspdb */
