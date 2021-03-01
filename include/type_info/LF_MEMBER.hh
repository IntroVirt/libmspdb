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
#ifndef LIBPDB_TYPE_INFO_LF_MEMBER_HH_
#define LIBPDB_TYPE_INFO_LF_MEMBER_HH_

#include "CV_Access.hh"
#include "CV_MethodProperty.hh"
#include "LF_MODIFIER.hh"
#include "LF_POINTER.hh"
#include "LF_TYPE.hh"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace mspdb {

class TypeInfoStream;

class LF_MEMBER : public LF_TYPE {
  public:
    LF_MEMBER(const char*& buf, int32_t& buffer_size, const TypeInfoStream& tpi);
    ~LF_MEMBER() override;

  public:
    const LF_TYPE& index() const;
    int64_t offset() const;
    const std::string& name() const;

    // Attributes
    CV_Access access_type() const;
    CV_MethodProperty method_property() const;
    bool pseudo() const;
    bool noinherit() const;
    bool noconstruct() const;
    bool compgenx() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_MEMBER_HH_ */