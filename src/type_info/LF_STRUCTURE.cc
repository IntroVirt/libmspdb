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
#include "type_info/LF_STRUCTURE.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"
#include "type_info/LF_FIELDLIST.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"
#include "CV_Property.hh"
#include "LF_VALUE.hh"

#include <cstring>
#include <iostream>
#include <mutex>

namespace mspdb {

#pragma pack(push, 1)

struct lfStructure {
    le_uint16_t count;
    CV_Property property;
    le_uint32_t field_list;
    le_uint32_t derived;
    le_uint32_t vshape;
};

#pragma pack(pop)

class LF_STRUCTURE::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    lfStructure entry;
    int64_t size;
    std::string name;
    const TypeInfoStream& tpi;
    std::vector<std::reference_wrapper<const LF_MEMBER>> field_list;
    std::mutex mtx;
};

uint16_t LF_STRUCTURE::count() const { return pImpl->entry.count; }

const std::vector<std::reference_wrapper<const LF_MEMBER>>& LF_STRUCTURE::field_list() const {
    std::lock_guard<std::mutex> lock(pImpl->mtx);
    if (pImpl->field_list.empty()) {
        if (unlikely(pImpl->entry.field_list == 0)) {
            throw pdb_exception("No field list in structure. Forward declaration?");
        }
        const auto& field_list = static_cast<const LF_FIELDLIST&>(
            pImpl->tpi.type(pImpl->entry.field_list, LEAF_TYPE::LF_FIELDLIST));
        for (const LF_TYPE& substruct : field_list.substructs()) {
            if (unlikely(substruct.type() != LEAF_TYPE::LF_MEMBER)) {
                throw pdb_exception("Invalid type " + to_string(substruct.type()) +
                                    " in LF_FIELDLIST");
            }
            pImpl->field_list.emplace_back(static_cast<const LF_MEMBER&>(substruct));
        }
    }
    return pImpl->field_list;
}
uint32_t LF_STRUCTURE::derived() const { return pImpl->entry.derived; }
uint32_t LF_STRUCTURE::vshape() const { return pImpl->entry.vshape; }
int64_t LF_STRUCTURE::size() const { return pImpl->size; }
const std::string& LF_STRUCTURE::name() const { return pImpl->name; }

bool LF_STRUCTURE::packed() const { return pImpl->entry.property.packed(); }
bool LF_STRUCTURE::ctor() const { return pImpl->entry.property.ctor(); }
bool LF_STRUCTURE::ovlops() const { return pImpl->entry.property.ovlops(); }
bool LF_STRUCTURE::nested() const { return pImpl->entry.property.nested(); }
bool LF_STRUCTURE::cnested() const { return pImpl->entry.property.cnested(); }
bool LF_STRUCTURE::opassign() const { return pImpl->entry.property.opassign(); }
bool LF_STRUCTURE::opcast() const { return pImpl->entry.property.opcast(); }
bool LF_STRUCTURE::fwdref() const { return pImpl->entry.property.fwdref(); }
bool LF_STRUCTURE::scoped() const { return pImpl->entry.property.scoped(); }

LF_STRUCTURE::LF_STRUCTURE(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_FIELDLIST_CONTAINER(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfStructure))) {
        throw pdb_exception("Buffer too small for LF_STRUCTURE");
    }

    pImpl->entry = *reinterpret_cast<const lfStructure*>(buffer);
    buffer += sizeof(lfStructure);
    buffer_size -= sizeof(lfStructure);

    LF_VALUE lfValue(buffer, buffer_size);
    pImpl->size = lfValue.value();
    pImpl->name = std::string(buffer, strnlen(buffer, buffer_size));
}

LF_STRUCTURE::~LF_STRUCTURE() = default;

} /* namespace mspdb */
