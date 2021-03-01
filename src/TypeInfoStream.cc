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
#include "TypeInfoStream.hh"
#include "Mapping.hh"
#include "pdb_exception.hh"

#include "type_info/LEAF_TYPE.hh"
#include "type_info/LF_BUILTIN.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <cassert>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace mspdb {

struct OffCb {
    le_int32_t off;
    le_int32_t cb;
};

struct TpiHash {
    le_uint16_t sn;
    le_uint16_t snPad;
    le_int32_t cbHashKey;
    le_int32_t cHashBuckets;
    OffCb offcbHashVals;
    OffCb offcbTiOff;
    OffCb offcbHashAdj;
};

struct _HDR {
    le_uint32_t vers;
    le_int32_t cbHdr;
    le_uint32_t tiMin;
    le_uint32_t tiMax;
    le_uint32_t cbGprec;
    TpiHash tpihash;
};

#pragma pack(push, 1)

using LE_LEAF_TYPE = le_type<LEAF_TYPE>;

struct RawType {
    le_uint16_t entry_size;
    LE_LEAF_TYPE leaf_type;
};

#pragma pack(pop)

class TypeInfoStream::IMPL {
  public:
    uint32_t min_type_id;
    std::unordered_map<BUILTIN_TYPE, std::unique_ptr<const LF_BUILTIN>> builtin_types;

    std::vector<std::shared_ptr<const LF_TYPE>> types;

    std::vector<std::reference_wrapper<const LF_CLASS>> classes;
    std::vector<std::reference_wrapper<const LF_ENUM>> enums;
    std::vector<std::reference_wrapper<const LF_STRUCTURE>> structs;
    std::vector<std::reference_wrapper<const LF_UNION>> unions;

    std::mutex mtx;
};

template <typename T>
std::shared_ptr<const LF_TYPE>
find_flattened(const T& lfType,
               const std::unordered_map<std::string, std::shared_ptr<const LF_TYPE>>& type_map) {

    auto iter = type_map.find(lfType.name());
    if (iter != type_map.end()) {
        // Safety check
        auto result = iter->second;
        assert(result->type() == lfType.type());
        return result;
    }
    return nullptr;
}

const std::vector<std::reference_wrapper<const LF_CLASS>>& TypeInfoStream::classes() const {
    return pImpl->classes;
}
const std::vector<std::reference_wrapper<const LF_ENUM>>& TypeInfoStream::enums() const {
    return pImpl->enums;
}
const std::vector<std::reference_wrapper<const LF_STRUCTURE>>& TypeInfoStream::structs() const {
    return pImpl->structs;
}
const std::vector<std::reference_wrapper<const LF_UNION>>& TypeInfoStream::unions() const {
    return pImpl->unions;
}

const LF_TYPE& TypeInfoStream::type(uint32_t type_id, LEAF_TYPE expected_type) const {
    const LF_TYPE& result = type(type_id);
    if (unlikely(result.type() != expected_type)) {
        throw pdb_exception("Expected type " + to_string(expected_type) + " but found " +
                            to_string(result.type()) + ": type_id " + std::to_string(type_id));
    }
    return result;
}

const LF_TYPE& TypeInfoStream::type(uint32_t type_id) const {
    const uint32_t index = type_id - pImpl->min_type_id;

    std::lock_guard<std::mutex> lock(pImpl->mtx);

    if (type_id < 0x700) {
        // Builtin type
        auto builtin_type_id = static_cast<BUILTIN_TYPE>(type_id);
        const auto it = pImpl->builtin_types.find(builtin_type_id);
        if (it != pImpl->builtin_types.end())
            return *(it->second);

        auto result = pImpl->builtin_types.try_emplace(
            builtin_type_id, std::make_unique<LF_BUILTIN>(builtin_type_id));
        return *(result.first->second);
    }

    if (unlikely(index >= pImpl->types.size())) {
        throw pdb_exception("Invalid type_id: " + std::to_string(type_id));
    }
    return *(pImpl->types.at(index));
}

template <typename T>
inline bool isFwdRef(const std::shared_ptr<const LF_TYPE>& lfType) {
    return static_cast<const T*>(lfType.get())->fwdref();
}

TypeInfoStream::TypeInfoStream(std::unique_ptr<const Mapping>&& mapping)
    : pImpl(std::make_unique<IMPL>()) {

    if (unlikely(sizeof(_HDR) > mapping->length())) {
        throw std::out_of_range("Mapping too small for TypeInfoStream header");
    }
    const _HDR* const hdr = reinterpret_cast<const _HDR*>(mapping->data());
    pImpl->min_type_id = hdr->tiMin;

    const unsigned int num_entries = (hdr->tiMax - hdr->tiMin);
    pImpl->types.reserve(num_entries);

    // This is only used for class/structure/union/enum types so we can flatten later
    std::unordered_map<std::string, std::shared_ptr<const LF_TYPE>> type_map(num_entries);

    const char* buffer = mapping->data() + hdr->cbHdr;
    for (unsigned int i = 0; i < num_entries; ++i) {
        const RawType* type = reinterpret_cast<const RawType*>(buffer);
        const char* data = buffer + sizeof(uint16_t); // Skip over the length
        buffer += sizeof(uint16_t) + type->entry_size;

        switch (type->leaf_type) {
        case LEAF_TYPE::LF_ARGLIST:
            pImpl->types.push_back(std::make_shared<LF_ARGLIST>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_ARRAY:
            pImpl->types.push_back(std::make_shared<LF_ARRAY>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_BITFIELD:
            pImpl->types.push_back(std::make_shared<LF_BITFIELD>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_CLASS: {
            auto lfClass = std::make_shared<LF_CLASS>(data, type->entry_size, *this);
            if (!lfClass->fwdref()) {
                pImpl->classes.push_back(*lfClass);
                type_map[lfClass->name()] = lfClass;
            }
            pImpl->types.push_back(std::move(lfClass));
            break;
        }
        case LEAF_TYPE::LF_ENUM: {
            auto lfEnum = std::make_shared<LF_ENUM>(data, type->entry_size, *this);
            if (!lfEnum->fwdref()) {
                pImpl->enums.push_back(*lfEnum);
                type_map[lfEnum->name()] = lfEnum;
            }
            pImpl->types.push_back(std::move(lfEnum));
            break;
        }
        case LEAF_TYPE::LF_FIELDLIST:
            pImpl->types.push_back(std::make_shared<LF_FIELDLIST>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_METHODLIST:
            pImpl->types.push_back(std::make_shared<LF_METHODLIST>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_MFUNCTION:
            pImpl->types.push_back(std::make_shared<LF_MFUNCTION>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_MODIFIER:
            pImpl->types.push_back(std::make_shared<LF_MODIFIER>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_POINTER:
            pImpl->types.push_back(std::make_shared<LF_POINTER>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_PROCEDURE:
            pImpl->types.push_back(std::make_shared<LF_PROCEDURE>(data, type->entry_size, *this));
            break;
        case LEAF_TYPE::LF_STRUCTURE: {
            auto lfStruct = std::make_shared<LF_STRUCTURE>(data, type->entry_size, *this);
            if (!lfStruct->fwdref()) {
                pImpl->structs.push_back(*lfStruct);
                type_map[lfStruct->name()] = lfStruct;
            }
            pImpl->types.push_back(std::move(lfStruct));
            break;
        }
        case LEAF_TYPE::LF_UNION: {
            auto lfUnion = std::make_shared<LF_UNION>(data, type->entry_size, *this);
            if (!lfUnion->fwdref()) {
                pImpl->unions.push_back(*lfUnion);
                type_map[lfUnion->name()] = lfUnion;
            }
            pImpl->types.push_back(std::move(lfUnion));
            break;
        }
        default:
            // Unhandled type! We didn't add anything, just continue the loop.
            // TODO: Logging
            throw pdb_exception("Unsupported type entry: " + to_string(type->leaf_type));
            continue;
        }
    }

    // Now do a second pass where we flatten everything
    for (size_t idx = 0; idx < pImpl->types.size(); ++idx) {
        std::shared_ptr<const LF_TYPE>& lfType = pImpl->types[idx];
        switch (lfType->type()) {
        case LEAF_TYPE::LF_CLASS:
        case LEAF_TYPE::LF_STRUCTURE:
        case LEAF_TYPE::LF_UNION:
            if (isFwdRef<LF_FIELDLIST_CONTAINER>(lfType)) {
                // If this is a forward ref, replace it with the real value
                auto result =
                    find_flattened(static_cast<const LF_FIELDLIST_CONTAINER&>(*lfType), type_map);
                if (result != nullptr) {
                    lfType = result;
                }
            }
            break;
        case LEAF_TYPE::LF_ENUM:
            if (isFwdRef<LF_ENUM>(lfType)) {
                // If this is a forward ref, replace it with the real value
                auto result = find_flattened(static_cast<const LF_ENUM&>(*lfType), type_map);
                if (result != nullptr) {
                    lfType = result;
                }
            }
            break;
        default:
            // We don't need to handle this on the second pass
            break;
        }
    }
}

TypeInfoStream::~TypeInfoStream() = default;

} /* namespace mspdb */
