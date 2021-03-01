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
#include "type_info/LF_ARGLIST.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

#include <mutex>
#include <vector>

namespace mspdb {

struct lfArgList {
    le_uint32_t count;
};

class LF_ARGLIST::IMPL {
  public:
    IMPL(const TypeInfoStream& tpi) : tpi(tpi) {}

  public:
    const TypeInfoStream& tpi;
    std::vector<uint32_t> arg_types;
    std::vector<std::reference_wrapper<const LF_TYPE>> resolved_arg_types;
    std::mutex mtx;
};

const std::vector<std::reference_wrapper<const LF_TYPE>>& LF_ARGLIST::arg_types() const {
    std::lock_guard<std::mutex> lock(pImpl->mtx);

    if (pImpl->resolved_arg_types.empty()) {
        pImpl->resolved_arg_types.reserve(pImpl->arg_types.size());
        for (auto arg_type : pImpl->arg_types) {
            pImpl->resolved_arg_types.emplace_back(pImpl->tpi.type(arg_type));
        }
    }
    return pImpl->resolved_arg_types;
}

LF_ARGLIST::LF_ARGLIST(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>(tpi)) {
    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)

    if (unlikely(buffer_size < sizeof(lfArgList))) {
        throw pdb_exception("Buffer size too small for LF_ARGLIST");
    }

    const auto* arglist = reinterpret_cast<const lfArgList*>(buffer);
    buffer += sizeof(lfArgList);
    buffer_size -= sizeof(lfArgList);

    if (unlikely(buffer_size < sizeof(uint32_t) * arglist->count)) {
        throw pdb_exception("Buffer size too small for LF_ARGLIST contents");
    }

    const auto* args = reinterpret_cast<const le_uint32_t*>(buffer);
    pImpl->arg_types.reserve(arglist->count);
    for (int i = 0; i < arglist->count; ++i) {
        pImpl->arg_types.push_back(args[i]);
    }
}

LF_ARGLIST::~LF_ARGLIST() = default;

} /* namespace mspdb */
