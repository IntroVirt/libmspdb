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
#include "type_info/LF_PROCEDURE.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

namespace mspdb {

#pragma pack(push, 1)

struct lfProcedure {
    le_uint32_t return_type;
    uint8_t calltype;
    uint8_t reserved;
    le_uint16_t param_count;
    uint32_t arg_list;
};

#pragma pack(pop)

class LF_PROCEDURE::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    lfProcedure entry;
};

const LF_TYPE& LF_PROCEDURE::return_type() const {
    return pImpl->tpi.type(pImpl->entry.return_type);
}
uint16_t LF_PROCEDURE::param_count() const { return pImpl->entry.param_count; }
const std::vector<std::reference_wrapper<const LF_TYPE>>& LF_PROCEDURE::arg_list() const {
    return static_cast<const LF_ARGLIST&>(
               pImpl->tpi.type(pImpl->entry.arg_list, LEAF_TYPE::LF_ARGLIST))
        .arg_types();
}

LF_PROCEDURE::LF_PROCEDURE(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfProcedure))) {
        throw pdb_exception("Buffer too small for LF_PROCEDURE");
    }
    pImpl->entry = *reinterpret_cast<const lfProcedure*>(buffer);
}

LF_PROCEDURE::~LF_PROCEDURE() = default;

} /* namespace mspdb */
