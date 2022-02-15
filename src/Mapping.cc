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
#include "Mapping.hh"
#include "PDB.hh"

#include "builtin_expect.hh"

#include <stdexcept>

#include <sys/mman.h>

namespace mspdb {

class Mapping::IMPL {
  public:
    IMPL(size_t length) : length(length) {

        // Allocate a buffer to hold the section
        data = reinterpret_cast<char*>(
            mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (unlikely(data == MAP_FAILED)) {
            throw std::runtime_error("Failed to map memory");
        }
    }
    ~IMPL() { munmap(data, length); }

  public:
    char* data;
    const uint32_t length;
};

char* Mapping::data() { return pImpl->data; }
const char* Mapping::data() const { return pImpl->data; }
const uint32_t Mapping::length() const { return pImpl->length; }

Mapping::Mapping(size_t length) : pImpl(std::make_unique<IMPL>(length)) {}

Mapping::Mapping(Mapping&&) noexcept = default;
Mapping& Mapping::operator=(Mapping&&) noexcept = default;
Mapping::~Mapping() = default;

} /* namespace mspdb */
