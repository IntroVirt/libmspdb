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
#include "type_info/LF_NESTTYPE.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"
#include "CV_FieldAttributes.hh"

#include <cstring>

namespace mspdb {

#pragma pack(push, 1)

struct lfNestType {
    CV_FieldAttributes attr;
    le_uint32_t index;
};

#pragma pack(pop)

class LF_NESTTYPE::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    struct lfNestType hdr;
    std::string name;
};

const LF_TYPE& LF_NESTTYPE::index() const { return pImpl->tpi.type(pImpl->hdr.index); }
const std::string& LF_NESTTYPE::name() const { return pImpl->name; }
CV_Access LF_NESTTYPE::access_type() const { return pImpl->hdr.attr.access_type(); }
CV_MethodProperty LF_NESTTYPE::method_property() const { return pImpl->hdr.attr.method_property(); }
bool LF_NESTTYPE::pseudo() const { return pImpl->hdr.attr.pseudo(); }
bool LF_NESTTYPE::noinherit() const { return pImpl->hdr.attr.noinherit(); }
bool LF_NESTTYPE::noconstruct() const { return pImpl->hdr.attr.noconstruct(); }
bool LF_NESTTYPE::compgenx() const { return pImpl->hdr.attr.compgenx(); }

LF_NESTTYPE::LF_NESTTYPE(const char*& buffer, int32_t& buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {

    if (unlikely(buffer_size < sizeof(lfNestType))) {
        throw pdb_exception("Buffer too small for LF_NESTTYPE");
    }

    pImpl->hdr = *reinterpret_cast<const lfNestType*>(buffer);
    buffer += sizeof(lfNestType);
    buffer_size -= sizeof(lfNestType);

    // The name should be next in the buffer
    const size_t name_len = strnlen(buffer, buffer_size);
    pImpl->name = std::string(buffer, name_len);
    buffer += (name_len + 1);
    buffer_size -= (name_len + 1);
}

LF_NESTTYPE::~LF_NESTTYPE() = default;

} // namespace mspdb