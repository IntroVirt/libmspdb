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
#include "type_info/LF_MEMBER.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"
#include "CV_FieldAttributes.hh"
#include "LF_VALUE.hh"

#include <cstring>

namespace mspdb {

using LE_LEAF_TYPE = le_type<LEAF_TYPE>;

#pragma pack(push, 1)

struct lfMember {
    CV_FieldAttributes attr;
    le_uint32_t index;
};

#pragma pack(pop)

class LF_MEMBER::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    lfMember hdr;
    int64_t offset;
    std::string name;
};

int64_t LF_MEMBER::offset() const { return pImpl->offset; }
const LF_TYPE& LF_MEMBER::index() const { return pImpl->tpi.type(pImpl->hdr.index); }
const std::string& LF_MEMBER::name() const { return pImpl->name; }
CV_Access LF_MEMBER::access_type() const { return pImpl->hdr.attr.access_type(); }
CV_MethodProperty LF_MEMBER::method_property() const { return pImpl->hdr.attr.method_property(); }
bool LF_MEMBER::pseudo() const { return pImpl->hdr.attr.pseudo(); }
bool LF_MEMBER::noinherit() const { return pImpl->hdr.attr.noinherit(); }
bool LF_MEMBER::noconstruct() const { return pImpl->hdr.attr.noconstruct(); }
bool LF_MEMBER::compgenx() const { return pImpl->hdr.attr.compgenx(); }

LF_MEMBER::LF_MEMBER(const char*& buffer, int32_t& buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {

    if (unlikely(buffer_size < sizeof(lfMember))) {
        throw pdb_exception("Buffer too small for LF_MEMBER");
    }

    pImpl->hdr = *reinterpret_cast<const lfMember*>(buffer);
    buffer += sizeof(lfMember);
    buffer_size -= sizeof(lfMember);

    LF_VALUE lfValue(buffer, buffer_size);
    pImpl->offset = lfValue.value();

    // The name should be next in the buffer
    const size_t name_len = strnlen(buffer, buffer_size);
    pImpl->name = std::string(buffer, name_len);
    buffer += (name_len + 1);
    buffer_size -= (name_len + 1);
}

LF_MEMBER::~LF_MEMBER() = default;

} /* namespace mspdb */
