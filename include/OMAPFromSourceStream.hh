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
#ifndef LIBPDB_OMAP_FROM_SOURCE_STREAM_HH_
#define LIBPDB_OMAP_FROM_SOURCE_STREAM_HH_

#include <cstdint>
#include <memory>

namespace mspdb {

class Mapping;

class OMAPEntry {
  public:
    OMAPEntry();
    OMAPEntry(uint32_t src, uint32_t dst);
    OMAPEntry(const OMAPEntry&);
    OMAPEntry& operator=(const OMAPEntry&);

  public:
    uint32_t sourceRVA() const;
    uint32_t destRVA() const;

  private:
    uint32_t src, dst;
};

class OMAPFromSourceStream {
  public:
    OMAPFromSourceStream(std::unique_ptr<const Mapping>&& mapping);
    OMAPFromSourceStream(OMAPFromSourceStream&&) noexcept;
    OMAPFromSourceStream& operator=(OMAPFromSourceStream&&) noexcept;
    ~OMAPFromSourceStream();

  public:
    OMAPEntry find(uint32_t rva) const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_OMAP_FROM_SOURCE_STREAM_HH_ */