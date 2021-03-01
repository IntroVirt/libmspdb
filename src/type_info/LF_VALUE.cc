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
#include "LF_VALUE.hh"
#include "pdb_exception.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

namespace mspdb {

using LE_LEAF_TYPE = le_type<LEAF_TYPE>;

#pragma pack(push, 1)

union lfVal {
    LE_LEAF_TYPE type;
    le_uint16_t value;
};

#pragma pack(pop)

#define GET_TYPE(T)                                                                                \
    if (unlikely(buffer_size < sizeof(T)))                                                         \
        throw pdb_exception("Buffer too small for " + to_string(val->type));                       \
    pImpl->value = *reinterpret_cast<const T*>(buffer);                                            \
    buffer += sizeof(T);                                                                           \
    buffer_size -= sizeof(T);

class LF_VALUE::IMPL {
  public:
    uint64_t value;
};

int64_t LF_VALUE::value() const { return pImpl->value; }

/**
 * @brief Internal helper class
 */
LF_VALUE::LF_VALUE(const char*& buffer, int32_t& buffer_size) : pImpl(std::make_unique<IMPL>()) {

    if (unlikely(buffer_size < sizeof(lfVal))) {
        throw pdb_exception("Buffer too small for LF_VALUE");
    }

    auto* val = reinterpret_cast<const lfVal*>(buffer);
    buffer += sizeof(lfVal);
    buffer_size -= sizeof(lfVal);

    if (val->value < 0x8000) {
        // The union represents a value directly
        pImpl->value = val->value;
    } else {
        // The union represents a type
        switch (val->type) {
        case LEAF_TYPE::LF_CHAR:
            GET_TYPE(int8_t);
            break;
        case LEAF_TYPE::LF_SHORT:
            GET_TYPE(int16_t);
            break;
        case LEAF_TYPE::LF_USHORT:
            GET_TYPE(uint16_t);
            break;
        case LEAF_TYPE::LF_LONG:
            GET_TYPE(int32_t);
            break;
        case LEAF_TYPE::LF_ULONG:
            GET_TYPE(uint32_t);
            break;
        default:
            throw pdb_exception("Unhandled type in LF_VALUE: " + to_string(val->type));
            break;
        }
    }
}

LF_VALUE::~LF_VALUE() = default;

} /* namespace mspdb  */
