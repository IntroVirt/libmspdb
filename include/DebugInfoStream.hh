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
#ifndef LIBPDB_DEBUG_INFO_STREAM_HH_
#define LIBPDB_DEBUG_INFO_STREAM_HH_

#include "DebugModuleInfo.hh"
#include "OptionalDebugHeader.hh"

#include <cstdint>
#include <memory>
#include <vector>

namespace mspdb {

class Mapping;

class DebugInfoStream {
  public:
    DebugInfoStream(std::unique_ptr<const Mapping>&& mapping);
    DebugInfoStream(DebugInfoStream&&) noexcept;
    DebugInfoStream& operator=(DebugInfoStream&&) noexcept;
    ~DebugInfoStream();

  public:
    int32_t version_signature() const;
    uint32_t version_header() const;
    uint16_t sym_record_stream() const;

    const DebugModuleInfo& module(uint16_t index) const;
    const std::vector<DebugModuleInfo>& modules() const;

    const OptionalDebugHeader& optional_debug_header() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_DEBUG_INFO_STREAM_HH_ */