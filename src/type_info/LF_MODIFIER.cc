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
#include "type_info/LF_MODIFIER.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

namespace mspdb {

#pragma pack(push, 1)

struct lfModifier {
    le_uint32_t modified_type;
    le_uint16_t modifiers;
};

#pragma pack(pop)

class LF_MODIFIER::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    lfModifier entry;
    const TypeInfoStream& tpi;
};

const LF_TYPE& LF_MODIFIER::modified_type() const {
    return pImpl->tpi.type(pImpl->entry.modified_type);
}

uint16_t LF_MODIFIER::modifiers() const { return pImpl->entry.modifiers; }
bool LF_MODIFIER::isconst() const {
    const static uint16_t CONST_MASK = (1u << 0);
    return pImpl->entry.modifiers & CONST_MASK;
}
bool LF_MODIFIER::isvolatile() const {
    const static uint16_t VOLATILE_MASK = (1u << 1);
    return pImpl->entry.modifiers & VOLATILE_MASK;
}
bool LF_MODIFIER::isunaligned() const {
    const static uint16_t UNALIGNED_MASK = (1u << 2);
    return pImpl->entry.modifiers & UNALIGNED_MASK;
}

LF_MODIFIER::LF_MODIFIER(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfModifier))) {
        throw pdb_exception("Buffer too small for LF_MODIFIER");
    }
    pImpl->entry = *reinterpret_cast<const lfModifier*>(buffer);
}

LF_MODIFIER::~LF_MODIFIER() = default;

} /* namespace mspdb */
