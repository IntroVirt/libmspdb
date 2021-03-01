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
#include "type_info/LF_FIELDLIST.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"
#include "type_info/LF_ENUMERATE.hh"
#include "type_info/LF_MEMBER.hh"
#include "type_info/LF_NESTTYPE.hh"

#include "../portable_endian.hh"

#include <cstring>
#include <iomanip>
#include <vector>

namespace mspdb {

using LE_LEAF_TYPE = le_type<LEAF_TYPE>;

#pragma pack(push, 1)

struct lfSubRecord {
    LE_LEAF_TYPE leaf_type;
};

#pragma pack(pop)

class LF_FIELDLIST::IMPL {
  public:
    std::vector<std::unique_ptr<LF_TYPE>> substructs_raw;
    std::vector<std::reference_wrapper<const LF_TYPE>> substructs;

  public:
};

const std::vector<std::reference_wrapper<const LF_TYPE>>& LF_FIELDLIST::substructs() const {
    return pImpl->substructs;
}

LF_FIELDLIST::LF_FIELDLIST(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>()) {

    // LF_TYPE advances our buffer/buffer_size past the "type" field (constructor takes references)
    while (buffer_size) {
        const auto* entry = reinterpret_cast<const lfSubRecord*>(buffer);
        // The constructors we call below modify buffer/buffer_size by reference
        switch (entry->leaf_type) {
        case LEAF_TYPE::LF_MEMBER:
            pImpl->substructs_raw.emplace_back(
                std::make_unique<LF_MEMBER>(buffer, buffer_size, tpi));
            pImpl->substructs.emplace_back(*pImpl->substructs_raw.back());
            break;
        case LEAF_TYPE::LF_ENUMERATE:
            pImpl->substructs_raw.emplace_back(std::make_unique<LF_ENUMERATE>(buffer, buffer_size));
            // pImpl->substructs.emplace_back(*pImpl->substructs_raw.back());
            break;
        case LEAF_TYPE::LF_NESTTYPE:
            // TODO: Figure out how this works
            // We don't directly get the offset for this, so do we have to figure it out outselves?

            pImpl->substructs_raw.emplace_back(
                std::make_unique<LF_NESTTYPE>(buffer, buffer_size, tpi));

            //
            // pImpl->substructs.emplace_back(*pImpl->substructs_raw.back());
            break;
        case LEAF_TYPE::LF_METHOD:
        case LEAF_TYPE::LF_BCLASS:
        default:
            return; // TODO
            throw pdb_exception("Unsupported LF_FIELDLIST entry: " + to_string(entry->leaf_type) +
                                " Remaining " + std::to_string(buffer_size));
            break;
        }

        // Pad to a 4-byte boundary
        const size_t entry_size = buffer - reinterpret_cast<const char*>(entry);
        const unsigned int next_multiple = ((entry_size + 3) / 4) * 4;
        const unsigned int padding = next_multiple - entry_size;
        buffer += padding;
        buffer_size -= padding;
    }
}

LF_FIELDLIST::~LF_FIELDLIST() = default;

} /* namespace mspdb */
