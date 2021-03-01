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
#ifndef LIBPDB_TYPE_INFO_LF_POINTER_HH_
#define LIBPDB_TYPE_INFO_LF_POINTER_HH_

#include "CV_PointerMode.hh"
#include "CV_PointerType.hh"
#include "LF_TYPE.hh"

#include <cstdint>
#include <memory>

namespace mspdb {

class TypeInfoStream;

class LF_POINTER : public LF_TYPE {
  public:
    LF_POINTER(const char* buf, int32_t buffer_size, const TypeInfoStream& tpi);
    ~LF_POINTER() override;

  public:
    const LF_TYPE& underlying_type() const;

    // Attributes
    uint32_t pointer_attributes() const;
    CV_PointerMode pointer_mode() const;
    CV_PointerType pointer_type() const;
    bool isflat32() const;
    bool isvolatile() const;
    bool isconst() const;
    bool isunaligned() const;
    bool isrestrict() const;
    uint16_t size() const;
    bool ismocom() const;
    bool islref() const;
    bool isrref() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_POINTER_HH_ */