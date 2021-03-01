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
#ifndef LIBPDB_IMAGE_SECTION_HEADER_HH_
#define LIBPDB_IMAGE_SECTION_HEADER_HH_

#include <cstdint>
#include <memory>
#include <string>

namespace mspdb {

class ImageSectionHeader {
  public:
    ImageSectionHeader(const char*& data, int32_t& buffer_len);
    ImageSectionHeader(ImageSectionHeader&&) noexcept;
    ImageSectionHeader& operator=(ImageSectionHeader&&) noexcept;
    ~ImageSectionHeader();

  public:
    const std::string& name() const;
    uint32_t physical_address() const;
    uint32_t virtual_size() const;
    uint32_t virtual_address() const;
    uint32_t sizeof_raw_data() const;
    uint32_t pointer_to_raw_data() const;
    uint32_t pointer_to_relocations() const;
    uint32_t pointer_to_line_numbers() const;
    uint16_t number_of_relocations() const;
    uint16_t number_of_line_numbers() const;
    uint32_t characteristics() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_IMAGE_SECTION_HEADER_HH_ */