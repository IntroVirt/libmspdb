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
#include "type_info/LF_CLASS.hh"

namespace mspdb {

class LF_CLASS::IMPL {
  public:
};

LF_CLASS::LF_CLASS(const char* buffer, int32_t buffer_size, const TypeInfoStream& tpi)
    : LF_STRUCTURE(buffer, buffer_size, tpi) {

    /* Same as LF_STRUCTURE, so we just extend that with no changes */
}

LF_CLASS::~LF_CLASS() = default;

} /* namespace mspdb */
