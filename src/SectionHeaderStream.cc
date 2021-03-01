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

#include "SectionHeaderStream.hh"
#include "Mapping.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <vector>

namespace mspdb {

class SectionHeaderStream::IMPL {
  public:
    IMPL(std::unique_ptr<const Mapping>&& mapping) {
        const char* buffer = mapping->data();
        int32_t remaining_buffer = mapping->length();

        while (remaining_buffer > 0) {
            /*
             * ImageSectionHeader() takes the pointer/length as reference variables.
             * They are updated for us when we call emplace_back().
             */
            try {
                section_headers.emplace_back(buffer, remaining_buffer);
            } catch (std::out_of_range& ex) {
                // Happens when there's extra padding at the end.
                return;
            }
        }
    }

  public:
    std::vector<ImageSectionHeader> section_headers;
};

const std::vector<ImageSectionHeader>& SectionHeaderStream::section_headers() const {
    return pImpl->section_headers;
}

SectionHeaderStream::SectionHeaderStream(std::unique_ptr<const Mapping>&& mapping)
    : pImpl(std::make_unique<IMPL>(std::move(mapping))) {}

SectionHeaderStream::SectionHeaderStream(SectionHeaderStream&&) noexcept = default;
SectionHeaderStream& SectionHeaderStream::operator=(SectionHeaderStream&&) noexcept = default;
SectionHeaderStream::~SectionHeaderStream() = default;

} /* namespace mspdb */
