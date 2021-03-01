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
#ifndef LIBPDB_TYPE_INFO_LF_ENUM_HH_
#define LIBPDB_TYPE_INFO_LF_ENUM_HH_

#include "LF_ENUMERATE.hh"
#include "LF_TYPE.hh"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mspdb {

class TypeInfoStream;

class LF_ENUM : public LF_TYPE {
  public:
    LF_ENUM(const char* buf, int32_t buffer_size, const TypeInfoStream& tpi);
    ~LF_ENUM() override;

  public:
    uint16_t count() const;
    const LF_TYPE& underlying_type() const;
    const std::vector<std::reference_wrapper<const LF_ENUMERATE>>& field_list() const;
    const std::string& name() const;

    // Flags
    bool packed() const;
    bool ctor() const;
    bool ovlops() const;
    bool nested() const;
    bool cnested() const;
    bool opassign() const;
    bool opcast() const;
    bool fwdref() const;
    bool scoped() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_ENUM_HH_ */