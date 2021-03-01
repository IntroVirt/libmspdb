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

#include "DebugInfoStream.hh"
#include "Mapping.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace mspdb {

struct DbiStreamHeader {
    le_int32_t VersionSignature;
    le_uint32_t VersionHeader;
    le_uint32_t Age;
    le_uint16_t GlobalStreamIndex;
    le_uint16_t BuildNumber;
    le_uint16_t PublicStreamIndex;
    le_uint16_t PdbDllVersion;
    le_uint16_t SymRecordStream;
    le_uint16_t PdbDllRbld;
    le_int32_t ModInfoSize;
    le_int32_t SectionContributionSize;
    le_int32_t SectionMapSize;
    le_int32_t SourceInfoSize;
    le_int32_t TypeServerSize;
    le_uint32_t MFCTypeServerIndex;
    le_int32_t OptionalDbgHeaderSize;
    le_int32_t ECSubstreamSize;
    le_uint16_t Flags;
    le_uint16_t Machine;
    le_uint32_t Padding;
};

class DebugInfoStream::IMPL {
  public:
    IMPL(std::unique_ptr<const Mapping>&& mapping) {
        if (unlikely(mapping->length() < sizeof(struct DbiStreamHeader))) {
            throw std::out_of_range("Buffer too small for DebugInfoStream header");
        }

        // Copy the header, we'll release the mapping when we're done to save memory
        dbi = *reinterpret_cast<const DbiStreamHeader*>(mapping->data());

        // Module Info Substream
        const size_t offset_module_info = sizeof(DbiStreamHeader);
        const char* buf = mapping->data() + offset_module_info;
        int32_t remaining_buffer = dbi.ModInfoSize;
        while (remaining_buffer) {
            /*
             * DebugModuleInfo() takes the pointer/length as reference variables.
             * They are updated for us when we call emplace_back().
             */
            modules.emplace_back(buf, remaining_buffer);
            DebugModuleInfo& module = modules.back();
            index_to_module[module.module_index()] = &module;
        }

        // TODO: Section Contribution Substream
        const size_t offset_section_contribution = offset_module_info + dbi.ModInfoSize;

        // TODO: Section Map Substream
        const size_t offset_section_map = offset_section_contribution + dbi.SectionContributionSize;

        // TODO: SourceInfo Substream
        const size_t offset_source_info = offset_section_map + dbi.SectionMapSize;

        // TODO: TypeServer Substream
        const size_t offset_type_server = offset_source_info + dbi.SourceInfoSize;

        // TODO: ECSubstreamSize Substream
        // const size_t offset_ec = offset_type_server + dbi.TypeServerSize;

        // Optional Debug Header Stream
        const size_t offset_optional_dbg_header = offset_type_server + dbi.ECSubstreamSize;
        optional_debug_header = std::make_unique<OptionalDebugHeader>(
            mapping->data() + offset_optional_dbg_header, dbi.OptionalDbgHeaderSize);
    }

  public:
    DbiStreamHeader dbi;
    std::vector<DebugModuleInfo> modules;
    std::map<uint16_t, DebugModuleInfo*> index_to_module;
    std::unique_ptr<OptionalDebugHeader> optional_debug_header;
};

int32_t DebugInfoStream::version_signature() const { return pImpl->dbi.VersionSignature; }

uint32_t DebugInfoStream::version_header() const { return pImpl->dbi.VersionHeader; }

uint16_t DebugInfoStream::sym_record_stream() const { return pImpl->dbi.SymRecordStream; }

const DebugModuleInfo& DebugInfoStream::module(uint16_t index) const {
    const auto it = pImpl->index_to_module.find(index);
    if (it != pImpl->index_to_module.end())
        return *(it->second);

    throw std::out_of_range("No module with index " + std::to_string(index));
}

const std::vector<DebugModuleInfo>& DebugInfoStream::modules() const { return pImpl->modules; }

const OptionalDebugHeader& DebugInfoStream::optional_debug_header() const {
    return *pImpl->optional_debug_header;
}

DebugInfoStream::DebugInfoStream(std::unique_ptr<const Mapping>&& mapping)
    : pImpl(std::make_unique<IMPL>(std::move(mapping))) {}

DebugInfoStream::DebugInfoStream(DebugInfoStream&&) noexcept = default;
DebugInfoStream& DebugInfoStream::operator=(DebugInfoStream&&) noexcept = default;
DebugInfoStream::~DebugInfoStream() = default;

} /* namespace mspdb */
