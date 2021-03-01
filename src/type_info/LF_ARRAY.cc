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
#include "type_info/LF_ARRAY.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"
#include "LF_VALUE.hh"

#include <cstring>

namespace mspdb {

#pragma pack(push, 1)

struct lfArray {
    le_uint32_t element_type;
    le_uint32_t index_type;
};

#pragma pack(pop)

class LF_ARRAY::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    lfArray entry;
    int64_t size;
    std::string name;
};

const LF_TYPE& LF_ARRAY::element_type() const { return pImpl->tpi.type(pImpl->entry.element_type); }
const LF_TYPE& LF_ARRAY::index_type() const { return pImpl->tpi.type(pImpl->entry.index_type); }
int64_t LF_ARRAY::size() const { return pImpl->size; }
const std::string& LF_ARRAY::name() const { return pImpl->name; }

LF_ARRAY::LF_ARRAY(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfArray))) {
        throw pdb_exception("Buffer too small for LF_ARRAY");
    }

    pImpl->entry = *reinterpret_cast<const lfArray*>(buffer);
    buffer += sizeof(lfArray);
    buffer_size -= sizeof(lfArray);

    LF_VALUE lfValue(buffer, buffer_size);
    pImpl->size = lfValue.value();

    pImpl->name = std::string(buffer, strnlen(buffer, buffer_size));
}

LF_ARRAY::~LF_ARRAY() = default;

} /* namespace mspdb */
