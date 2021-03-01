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
#include "type_info/LF_FIELDLIST_CONTAINER.hh"
#include "TypeInfoStream.hh"
#include "pdb_exception.hh"
#include "type_info/LF_FIELDLIST.hh"
#include "type_info/LF_MODIFIER.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

#include <cstring>
#include <iostream>
#include <mutex>
#include <unordered_map>

namespace mspdb {

class LF_FIELDLIST_CONTAINER::IMPL {
  public:
    std::unordered_map<std::string, std::reference_wrapper<const LF_MEMBER>> name_to_field;
    std::mutex mtx;
};

const LF_MEMBER* LF_FIELDLIST_CONTAINER::find_member(const std::string& name) const {
    std::lock_guard<std::mutex> lock(pImpl->mtx);

    if (pImpl->name_to_field.empty()) {
        // Build the map
        for (const LF_MEMBER& member : field_list()) {
            pImpl->name_to_field.try_emplace(member.name(), std::ref(member));
        }
    }

    auto iter = pImpl->name_to_field.find(name);
    if (iter != pImpl->name_to_field.end()) {
        return &(iter->second.get());
    }
    return nullptr;
}

template <typename T>
static inline const LF_MEMBER* recurse(const LF_TYPE& index, const std::string& name,
                                       size_t& total_offset) {
    const T& lfStruct = static_cast<const T&>(index);
    if (lfStruct.fwdref()) {
        return nullptr;
    }
    return lfStruct.find_member_recursive(name, total_offset);
}

const LF_MEMBER* LF_FIELDLIST_CONTAINER::find_member_recursive(const std::string& name,
                                                               size_t& total_offset) const {
    // Check if this structure contains the target directly
    auto member = find_member(name);
    if (member != nullptr) {
        // Found it!
        total_offset += member->offset();
        return member;
    }

    // Didn't find it, check all of our child structures
    for (const LF_MEMBER& member : field_list()) {
        // Some indirection to handle modifiers
        const LF_TYPE* index = &(member.index());
        while (index->type() == LEAF_TYPE::LF_MODIFIER) {
            index = &(static_cast<const LF_MODIFIER*>(index)->modified_type());
        }

        switch (index->type()) {
        case LEAF_TYPE::LF_CLASS:
        case LEAF_TYPE::LF_STRUCTURE:
        case LEAF_TYPE::LF_UNION: {
            // Start our offset at the base of this member.
            size_t struct_offset = total_offset + member.offset();
            const auto* search = recurse<LF_FIELDLIST_CONTAINER>(*index, name, struct_offset);
            if (search != nullptr) {
                // We found it
                total_offset = struct_offset;
                return search;
            }
            break;
        }
        default:
            break;
        }
    }
    return nullptr;
}

LF_FIELDLIST_CONTAINER::LF_FIELDLIST_CONTAINER(const char*& buffer, int32_t& buffer_size)
    : LF_TYPE(buffer, buffer_size), pImpl(std::make_unique<IMPL>()) {}

LF_FIELDLIST_CONTAINER::~LF_FIELDLIST_CONTAINER() = default;

} /* namespace mspdb */
