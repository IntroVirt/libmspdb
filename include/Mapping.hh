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
#ifndef LIBPDB_MAPPING_HH_
#define LIBPDB_MAPPING_HH_

#include <memory>

namespace mspdb {

class PDB;

/**
 * @brief A normalized PDB block map
 */
class Mapping {
  public:
    /**
     * @brief create a new mapping
     * @param length The length of the data
     */
    Mapping(size_t length);
    Mapping(Mapping&&) noexcept;
    Mapping& operator=(Mapping&&) noexcept;
    ~Mapping();

  public:
    char* data();
    const char* data() const;

    const uint32_t length() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_MAPPING_HH_ */