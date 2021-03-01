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
#include "type_info/LF_BITFIELD.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

namespace mspdb {

#pragma pack(push, 1)

struct lfBitfield {
    le_uint32_t base_type;
    uint8_t length;
    uint8_t position;
};

#pragma pack(pop)

class LF_BITFIELD::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    lfBitfield entry;
};

const LF_TYPE& LF_BITFIELD::base_type() const { return pImpl->tpi.type(pImpl->entry.base_type); }
uint16_t LF_BITFIELD::length() const { return pImpl->entry.length; }
uint16_t LF_BITFIELD::position() const { return pImpl->entry.position; }

LF_BITFIELD::LF_BITFIELD(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfBitfield))) {
        throw pdb_exception("Buffer too small for LF_BITFIELD");
    }

    pImpl->entry = *reinterpret_cast<const lfBitfield*>(buffer);
}

LF_BITFIELD::~LF_BITFIELD() = default;

} /* namespace mspdb */
