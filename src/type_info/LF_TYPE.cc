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
#include "type_info/LF_TYPE.hh"

#include "../builtin_expect.hh"
#include "../portable_endian.hh"

#include <stdexcept>

namespace mspdb {

using LE_LEAF_TYPE = le_type<LEAF_TYPE>;

class LF_TYPE::IMPL {
  public:
    LEAF_TYPE type;
};

LEAF_TYPE LF_TYPE::type() const { return pImpl->type; }

LF_TYPE::LF_TYPE(LEAF_TYPE type) : pImpl(std::make_unique<IMPL>()) { pImpl->type = type; }

LF_TYPE::LF_TYPE(const char*& buffer, int32_t& buffer_size) : pImpl(std::make_unique<IMPL>()) {

    if (unlikely(buffer_size < sizeof(LEAF_TYPE))) {
        throw std::out_of_range("Buffer too small to read LEAF_TYPE");
    }
    pImpl->type = *reinterpret_cast<const LE_LEAF_TYPE*>(buffer);
    buffer += sizeof(LEAF_TYPE);
    buffer_size -= sizeof(LEAF_TYPE);
}

LF_TYPE::~LF_TYPE() = default;

} /* namespace mspdb */
