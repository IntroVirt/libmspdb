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

#include "ImageSectionHeader.hh"
#include "pdb_exception.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <cstring>
#include <iostream>

namespace mspdb {

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union {
        le_uint32_t PhysicalAddress;
        le_uint32_t VirtualSize;
    };
    le_uint32_t VirtualAddress;
    le_uint32_t SizeOfRawData;
    le_uint32_t PointerToRawData;
    le_uint32_t PointerToRelocations;
    le_uint32_t PointerToLineNumbers;
    le_uint16_t NumberOfRelocations;
    le_uint16_t NumberOfLineNumbers;
    le_uint32_t Characteristics;
};

class ImageSectionHeader::IMPL {
  public:
    IMPL(const char*& data, int32_t& buffer_len) {
        if (unlikely(buffer_len < sizeof(IMAGE_SECTION_HEADER))) {
            hdr = {};
            data += sizeof(IMAGE_SECTION_HEADER);
            buffer_len -= sizeof(IMAGE_SECTION_HEADER);
            return;
            // throw std::out_of_range("Buffer too small for ImageSectionHeader: " +
            // std::to_string(buffer_len) + "/" + std::to_string(sizeof(IMAGE_SECTION_HEADER)));
        }
        hdr = *reinterpret_cast<const IMAGE_SECTION_HEADER*>(data);
        name = std::string(hdr.Name, strnlen(hdr.Name, sizeof(hdr.Name)));

        if (name.empty()) {
            // Not sure if this is correct, but it avoids a bunch of null entries.
            // We need at least one null entry for symbols that aren't part of a section.
            buffer_len = 0;
            return;
        }

        data += sizeof(IMAGE_SECTION_HEADER);
        buffer_len -= sizeof(IMAGE_SECTION_HEADER);
    }

  public:
    struct IMAGE_SECTION_HEADER hdr;
    std::string name;
};

const std::string& ImageSectionHeader::name() const { return pImpl->name; }
uint32_t ImageSectionHeader::physical_address() const { return pImpl->hdr.PhysicalAddress; }
uint32_t ImageSectionHeader::virtual_size() const { return pImpl->hdr.VirtualSize; }
uint32_t ImageSectionHeader::virtual_address() const { return pImpl->hdr.VirtualAddress; }
uint32_t ImageSectionHeader::sizeof_raw_data() const { return pImpl->hdr.SizeOfRawData; }
uint32_t ImageSectionHeader::pointer_to_raw_data() const { return pImpl->hdr.PointerToRawData; }
uint32_t ImageSectionHeader::pointer_to_relocations() const {
    return pImpl->hdr.PointerToRelocations;
}
uint32_t ImageSectionHeader::pointer_to_line_numbers() const {
    return pImpl->hdr.PointerToLineNumbers;
}
uint16_t ImageSectionHeader::number_of_relocations() const {
    return pImpl->hdr.NumberOfRelocations;
}
uint16_t ImageSectionHeader::number_of_line_numbers() const {
    return pImpl->hdr.NumberOfLineNumbers;
}
uint32_t ImageSectionHeader::characteristics() const { return pImpl->hdr.Characteristics; }

ImageSectionHeader::ImageSectionHeader(const char*& data, int32_t& buffer_len)
    : pImpl(std::make_unique<IMPL>(data, buffer_len)) {}
ImageSectionHeader::ImageSectionHeader(ImageSectionHeader&&) noexcept = default;
ImageSectionHeader& ImageSectionHeader::operator=(ImageSectionHeader&&) noexcept = default;
ImageSectionHeader::~ImageSectionHeader() = default;

} /* namespace mspdb */
