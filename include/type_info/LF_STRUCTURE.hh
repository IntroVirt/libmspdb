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
#ifndef LIBPDB_TYPE_INFO_LF_STRUCTURE_HH_
#define LIBPDB_TYPE_INFO_LF_STRUCTURE_HH_

#include "LF_FIELDLIST_CONTAINER.hh"
#include "LF_MEMBER.hh"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mspdb {

class TypeInfoStream;

class LF_STRUCTURE : public LF_FIELDLIST_CONTAINER {
  public:
    LF_STRUCTURE(const char* buf, int32_t buffer_size, const TypeInfoStream& tpi);
    ~LF_STRUCTURE() override;

  public:
    uint16_t count() const override;
    const std::vector<std::reference_wrapper<const LF_MEMBER>>& field_list() const override;
    uint32_t derived() const;
    uint32_t vshape() const;
    int64_t size() const override;
    const std::string& name() const override;

    // Flags
    bool packed() const override;
    bool ctor() const override;
    bool ovlops() const override;
    bool nested() const override;
    bool cnested() const override;
    bool opassign() const override;
    bool opcast() const override;
    bool fwdref() const override;
    bool scoped() const override;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_STRUCTURE_HH_ */