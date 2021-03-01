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

#include "OptionalDebugHeader.hh"
#include "pdb_exception.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <cstring>

namespace mspdb {

struct DbgHdr {
    le_uint16_t snFPO;
    le_uint16_t snException;
    le_uint16_t snFixup;
    le_uint16_t snOmapToSrc;
    le_uint16_t snOmapFromSrc;
    le_uint16_t snSectionHdr;
    le_uint16_t snTokenRidMap;
    le_uint16_t snXdata;
    le_uint16_t snPdata;
    le_uint16_t snNewFPO;
    le_uint16_t snSectionHdrOrig;
};

class OptionalDebugHeader::IMPL {
  public:
    IMPL(const char* data, int32_t buffer_len) {
        if (unlikely(buffer_len < sizeof(DbgHdr))) {
            throw std::out_of_range("Buffer too small for OptionalDebugHeader");
        }
        dbghdr = *reinterpret_cast<const struct DbgHdr*>(data);
    }

  public:
    struct DbgHdr dbghdr;
};

uint16_t OptionalDebugHeader::fpo_stream() const { return pImpl->dbghdr.snFPO; }
uint16_t OptionalDebugHeader::exception_stream() const { return pImpl->dbghdr.snException; }
uint16_t OptionalDebugHeader::fixup_stream() const { return pImpl->dbghdr.snFixup; }
uint16_t OptionalDebugHeader::omap_to_src_stream() const { return pImpl->dbghdr.snOmapToSrc; }
uint16_t OptionalDebugHeader::omap_from_src_stream() const { return pImpl->dbghdr.snOmapFromSrc; }
uint16_t OptionalDebugHeader::section_hdr_stream() const { return pImpl->dbghdr.snSectionHdr; }
uint16_t OptionalDebugHeader::token_rid_map_stream() const { return pImpl->dbghdr.snTokenRidMap; }
uint16_t OptionalDebugHeader::xdata_stream() const { return pImpl->dbghdr.snXdata; }
uint16_t OptionalDebugHeader::pdata_stream() const { return pImpl->dbghdr.snPdata; }
uint16_t OptionalDebugHeader::new_fpo_stream() const { return pImpl->dbghdr.snNewFPO; }
uint16_t OptionalDebugHeader::section_hdr_orig_stream() const {
    return pImpl->dbghdr.snSectionHdrOrig;
}

OptionalDebugHeader::OptionalDebugHeader(const char* data, int32_t buffer_len)
    : pImpl(std::make_unique<IMPL>(data, buffer_len)) {}
OptionalDebugHeader::OptionalDebugHeader(OptionalDebugHeader&&) noexcept = default;
OptionalDebugHeader& OptionalDebugHeader::operator=(OptionalDebugHeader&&) noexcept = default;
OptionalDebugHeader::~OptionalDebugHeader() = default;

} /* namespace mspdb */
