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
#ifndef LIBPDB_TYPE_INFO_LF_BUILTIN_HH_
#define LIBPDB_TYPE_INFO_LF_BUILTIN_HH_

#include "BUILTIN_TYPE.hh"
#include "LF_TYPE.hh"

#include <cstdint>
#include <memory>
#include <string>

namespace mspdb {

/**
 * @brief This is not a real PDB structure, just something we use to help simplify the code.
 */
class LF_BUILTIN : public LF_TYPE {
  public:
    LF_BUILTIN(BUILTIN_TYPE type);
    ~LF_BUILTIN() override;

  public:
    BUILTIN_TYPE builtin_type() const;

    /**
     * @returns True if this type is a pointer.
     */
    bool pointer() const;

    int64_t size() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_LF_BUILTIN_HH_ */