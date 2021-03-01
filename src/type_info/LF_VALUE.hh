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
#ifndef LIBMSPDB_TYPE_INFO_LF_VALUE_HH_
#define LIBMSPDB_TYPE_INFO_LF_VALUE_HH_

#include "type_info/LEAF_TYPE.hh"

#include <cstdint>
#include <memory>

namespace mspdb {

/**
 * @brief internal helper class
 */
class LF_VALUE {
  public:
    LF_VALUE(const char*& buffer, int32_t& buffer_size);
    ~LF_VALUE();

  public:
    int64_t value() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb  */

#endif /* LIBMSPDB_TYPE_INFO_LF_VALUE_HH_ */
