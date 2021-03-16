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
#ifndef LIBPDB_TYPE_INFO_LF_FIELD_CONTAINER_HH_
#define LIBPDB_TYPE_INFO_LF_FIELD_CONTAINER_HH_

#include "LF_MEMBER.hh"
#include "LF_TYPE.hh"

#include <cstdint>
#include <memory>
#include <vector>

namespace mspdb {

class LF_FIELDLIST_CONTAINER : public LF_TYPE {
  public:
    LF_FIELDLIST_CONTAINER(const char*& buf, int32_t& buffer_size);
    ~LF_FIELDLIST_CONTAINER() override;

  public:
    virtual uint16_t count() const = 0;
    virtual const std::vector<std::reference_wrapper<const LF_MEMBER>>& field_list() const = 0;
    virtual int64_t size() const = 0;
    virtual const std::string& name() const = 0;

    const LF_MEMBER* find_member(const std::string& name) const;
    const LF_MEMBER* find_member_recursive(const std::string& name, size_t& total_offset) const;

    // Flags
    virtual bool packed() const = 0;
    virtual bool ctor() const = 0;
    virtual bool ovlops() const = 0;
    virtual bool nested() const = 0;
    virtual bool cnested() const = 0;
    virtual bool opassign() const = 0;
    virtual bool opcast() const = 0;
    virtual bool fwdref() const = 0;
    virtual bool scoped() const = 0;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_FIELD_CONTAINER_HH_ */