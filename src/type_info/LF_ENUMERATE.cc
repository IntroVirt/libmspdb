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
#include "type_info/LF_ENUMERATE.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"
#include "CV_FieldAttributes.hh"
#include "LF_VALUE.hh"

#include <cstring>

namespace mspdb {

using LE_LEAF_TYPE = le_type<LEAF_TYPE>;

#pragma pack(push, 1)

struct lfEnumerate {
    CV_FieldAttributes attr;
};

#pragma pack(pop)

class LF_ENUMERATE::IMPL {
  public:
    lfEnumerate hdr;
    uint64_t enum_value;
    std::string name;
};

int64_t LF_ENUMERATE::enum_value() const { return pImpl->enum_value; }

const std::string& LF_ENUMERATE::name() const { return pImpl->name; }

CV_Access LF_ENUMERATE::access_type() const { return pImpl->hdr.attr.access_type(); }
CV_MethodProperty LF_ENUMERATE::method_property() const {
    return pImpl->hdr.attr.method_property();
}
bool LF_ENUMERATE::pseudo() const { return pImpl->hdr.attr.pseudo(); }
bool LF_ENUMERATE::noinherit() const { return pImpl->hdr.attr.noinherit(); }
bool LF_ENUMERATE::noconstruct() const { return pImpl->hdr.attr.noconstruct(); }
bool LF_ENUMERATE::compgenx() const { return pImpl->hdr.attr.compgenx(); }

LF_ENUMERATE::LF_ENUMERATE(const char*& buffer, int32_t& buffer_size)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>()) {

    if (unlikely(buffer_size < sizeof(lfEnumerate))) {
        throw pdb_exception("Buffer too small for LF_ENUMERATE");
    }

    pImpl->hdr = *reinterpret_cast<const lfEnumerate*>(buffer);
    buffer += sizeof(lfEnumerate);
    buffer_size -= sizeof(lfEnumerate);

    LF_VALUE lfValue(buffer, buffer_size);
    pImpl->enum_value = lfValue.value();

    // The name should be next in the buffer
    const size_t name_len = strnlen(buffer, buffer_size);
    pImpl->name = std::string(buffer, name_len);
    buffer += (name_len + 1);
    buffer_size -= (name_len + 1);
}

LF_ENUMERATE::~LF_ENUMERATE() = default;

} /* namespace mspdb */
