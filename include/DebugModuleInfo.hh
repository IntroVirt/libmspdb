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
#ifndef LIBPDB_DEBUG_MODULE_INFO_HH_
#define LIBPDB_DEBUG_MODULE_INFO_HH_

#include <cstdint>
#include <memory>

namespace mspdb {

class DebugModuleInfo {
  public:
    DebugModuleInfo(const char*& data, int32_t& buffer_len);
    DebugModuleInfo(DebugModuleInfo&&) noexcept;
    DebugModuleInfo& operator=(DebugModuleInfo&&) noexcept;
    ~DebugModuleInfo();

  public:
    uint16_t section() const;
    int32_t offset() const;
    int32_t size() const;

    uint16_t module_index() const;
    uint32_t module_sym_stream() const;
    uint32_t sym_byte_size() const;
    uint16_t source_file_count() const;

    const std::string& module_name() const;
    const std::string& obj_filename() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_DEBUG_MODULE_INFO_HH_ */