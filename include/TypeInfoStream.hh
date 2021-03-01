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
#ifndef LIBPDB_TYPE_INFO_STREAM_HH_
#define LIBPDB_TYPE_INFO_STREAM_HH_

#include "type_info/lf_types.hh"

#include <functional>
#include <memory>
#include <vector>

namespace mspdb {

class Mapping;

class TypeInfoStream {
  public:
    TypeInfoStream(std::unique_ptr<const Mapping>&& mapping);
    ~TypeInfoStream();

  public:
    const std::vector<std::reference_wrapper<const LF_CLASS>>& classes() const;
    const std::vector<std::reference_wrapper<const LF_ENUM>>& enums() const;
    const std::vector<std::reference_wrapper<const LF_STRUCTURE>>& structs() const;
    const std::vector<std::reference_wrapper<const LF_UNION>>& unions() const;

    const LF_TYPE& type(uint32_t type_id, LEAF_TYPE expected_type) const;
    const LF_TYPE& type(uint32_t type_id) const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_STREAM_HH_*/
