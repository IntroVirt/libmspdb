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
#ifndef LIBPDB_TYPE_INFO_LF_ARRAY_HH_
#define LIBPDB_TYPE_INFO_LF_ARRAY_HH_

#include "LF_TYPE.hh"

#include <cstdint>
#include <memory>
#include <string>

namespace mspdb {

class TypeInfoStream;

class LF_ARRAY : public LF_TYPE {
  public:
    LF_ARRAY(const char* buf, int32_t buffer_size, const TypeInfoStream& tpi);
    ~LF_ARRAY() override;

  public:
    const LF_TYPE& element_type() const;
    const LF_TYPE& index_type() const;
    int64_t size() const;
    const std::string& name() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_ARRAY_HH_ */