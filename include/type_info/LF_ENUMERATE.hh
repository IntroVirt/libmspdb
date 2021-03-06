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
#ifndef LIBPDB_TYPE_INFO_LF_ENUMERATE_HH_
#define LIBPDB_TYPE_INFO_LF_ENUMERATE_HH_

#include "CV_Access.hh"
#include "CV_MethodProperty.hh"
#include "LF_TYPE.hh"

#include <cstdint>
#include <memory>

namespace mspdb {

class LF_ENUMERATE : public LF_TYPE {
  public:
    LF_ENUMERATE(const char*& buf, int32_t& buffer_size);
    ~LF_ENUMERATE() override;

  public:
    int64_t enum_value() const;
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

#endif /* LIBPDB_TYPE_INFO_LF_ENUMERATE_HH_ */