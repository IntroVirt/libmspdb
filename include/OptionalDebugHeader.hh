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
#ifndef LIBPDB_OPTIONAL_DEBUG_HEADER_HH_
#define LIBPDB_OPTIONAL_DEBUG_HEADER_HH_

#include <cstdint>
#include <memory>

namespace mspdb {

class Mapping;

class OptionalDebugHeader {
  public:
    OptionalDebugHeader(const char* data, int32_t buffer_len);
    OptionalDebugHeader(OptionalDebugHeader&&) noexcept;
    OptionalDebugHeader& operator=(OptionalDebugHeader&&) noexcept;
    ~OptionalDebugHeader();

  public:
    uint16_t fpo_stream() const;
    uint16_t exception_stream() const;
    uint16_t fixup_stream() const;
    uint16_t omap_to_src_stream() const;
    uint16_t omap_from_src_stream() const;
    uint16_t section_hdr_stream() const;
    uint16_t token_rid_map_stream() const;
    uint16_t xdata_stream() const;
    uint16_t pdata_stream() const;
    uint16_t new_fpo_stream() const;
    uint16_t section_hdr_orig_stream() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_OPTIONAL_DEBUG_HEADER_HH_ */