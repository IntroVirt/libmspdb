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

#include "OMAPFromSourceStream.hh"
#include "Mapping.hh"

#include "portable_endian.hh"

#include <map>

namespace mspdb {

OMAPEntry::OMAPEntry() : src(0), dst(0) {}

OMAPEntry::OMAPEntry(uint32_t src, uint32_t dst) : src(src), dst(dst) {}

OMAPEntry::OMAPEntry(const OMAPEntry&) = default;
OMAPEntry& OMAPEntry::operator=(const OMAPEntry&) = default;

uint32_t OMAPEntry::sourceRVA() const { return src; }
uint32_t OMAPEntry::destRVA() const { return dst; }

struct OMAP_DATA {
    le_uint32_t rva;
    le_uint32_t rvaTo;
};

class OMAPFromSourceStream::IMPL {
  public:
    IMPL(std::unique_ptr<const Mapping>&& mapping) {
        int32_t buffer_remaining = mapping->length();
        auto* entry = reinterpret_cast<const OMAP_DATA*>(mapping->data());

        while (buffer_remaining) {
            omap[entry->rva] = OMAPEntry(entry->rva, entry->rvaTo);
            buffer_remaining -= sizeof(OMAP_DATA);
            ++entry;
        }
    }

  public:
    std::map<uint32_t, OMAPEntry> omap;
};

OMAPEntry OMAPFromSourceStream::find(uint32_t rva) const {
    const auto it = pImpl->omap.lower_bound(rva);
    if (it != pImpl->omap.end()) {
        return it->second;
    }
    // TODO: Can this actually happen?
    return OMAPEntry(0, 0);
}

OMAPFromSourceStream::OMAPFromSourceStream(std::unique_ptr<const Mapping>&& mapping)
    : pImpl(std::make_unique<IMPL>(std::move(mapping))) {}

OMAPFromSourceStream::OMAPFromSourceStream(OMAPFromSourceStream&&) noexcept = default;
OMAPFromSourceStream& OMAPFromSourceStream::operator=(OMAPFromSourceStream&&) noexcept = default;
OMAPFromSourceStream::~OMAPFromSourceStream() = default;

} /* namespace mspdb */
