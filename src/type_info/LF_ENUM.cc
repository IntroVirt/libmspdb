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
#include "type_info/LF_ENUM.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"
#include "CV_Property.hh"

#include <cstring>
#include <mutex>

namespace mspdb {

struct lfEnum {
    le_uint16_t count;
    CV_Property property;
    le_uint32_t utype;
    le_uint32_t field_list;
    // char name[];
};

class LF_ENUM::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    lfEnum entry;
    std::string name;
    const TypeInfoStream& tpi;
    std::vector<std::reference_wrapper<const LF_ENUMERATE>> field_list;
    std::mutex mtx;
};

uint16_t LF_ENUM::count() const { return pImpl->entry.count; }
const LF_TYPE& LF_ENUM::underlying_type() const { return pImpl->tpi.type(pImpl->entry.utype); }
const std::vector<std::reference_wrapper<const LF_ENUMERATE>>& LF_ENUM::field_list() const {
    std::lock_guard<std::mutex> lock(pImpl->mtx);

    if (pImpl->field_list.empty()) {
        if (unlikely(pImpl->entry.field_list == 0)) {
            throw pdb_exception("No field list in structure. Forward declaration?");
        }
        const auto& field_list = static_cast<const LF_FIELDLIST&>(
            pImpl->tpi.type(pImpl->entry.field_list, LEAF_TYPE::LF_FIELDLIST));
        for (const LF_TYPE& substruct : field_list.substructs()) {
            if (unlikely(substruct.type() != LEAF_TYPE::LF_ENUMERATE)) {
                throw pdb_exception("Invalid type " + to_string(substruct.type()) +
                                    " in LF_FIELDLIST");
            }
            pImpl->field_list.emplace_back(static_cast<const LF_ENUMERATE&>(substruct));
        }
    }

    return pImpl->field_list;
}
const std::string& LF_ENUM::name() const { return pImpl->name; }

bool LF_ENUM::packed() const { return pImpl->entry.property.packed(); }
bool LF_ENUM::ctor() const { return pImpl->entry.property.ctor(); }
bool LF_ENUM::ovlops() const { return pImpl->entry.property.ovlops(); }
bool LF_ENUM::nested() const { return pImpl->entry.property.nested(); }
bool LF_ENUM::cnested() const { return pImpl->entry.property.cnested(); }
bool LF_ENUM::opassign() const { return pImpl->entry.property.opassign(); }
bool LF_ENUM::opcast() const { return pImpl->entry.property.opcast(); }
bool LF_ENUM::fwdref() const { return pImpl->entry.property.fwdref(); }
bool LF_ENUM::scoped() const { return pImpl->entry.property.scoped(); }

LF_ENUM::LF_ENUM(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfEnum))) {
        throw pdb_exception("Buffer too small for LF_ENUM");
    }
    pImpl->entry = *reinterpret_cast<const lfEnum*>(buffer);
    buffer += sizeof(lfEnum);
    buffer_size -= sizeof(lfEnum);

    pImpl->name = std::string(buffer, strnlen(buffer, buffer_size));
}

LF_ENUM::~LF_ENUM() = default;

} /* namespace mspdb */
