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
#ifndef LIBPDB_TYPE_INFO_LF_FIELDLIST_HH_
#define LIBPDB_TYPE_INFO_LF_FIELDLIST_HH_

#include "LF_TYPE.hh"

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace mspdb {

class TypeInfoStream;

class LF_FIELDLIST : public LF_TYPE {
  public:
    LF_FIELDLIST(const char* buf, int32_t buffer_size, const TypeInfoStream& tpi);
    ~LF_FIELDLIST() override;

  public:
    const std::vector<std::reference_wrapper<const LF_TYPE>>& substructs() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_FIELDLIST_HH_ */