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
#pragma once

#include "LF_TYPE.hh"

#include "CV_Access.hh"
#include "CV_MethodProperty.hh"

namespace mspdb {

class TypeInfoStream;

class LF_NESTTYPE : public LF_TYPE {
  public:
    LF_NESTTYPE(const char*& buffer, int32_t& buffer_size, const TypeInfoStream& tpi);
    ~LF_NESTTYPE() override;

  public:
    const LF_TYPE& index() const;
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

} // namespace mspdb