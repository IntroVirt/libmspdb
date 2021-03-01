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
#include "StreamDirectory.hh"

#include "Mapping.hh"
#include "PDB.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <cmath>
#include <map>
#include <stdexcept>

namespace mspdb {

class StreamDirectory::IMPL {
  public:
    IMPL(const PDB& pdb, const char* file_data) {
        // Map the stream directory
        const char* block_map = file_data + (pdb.block_map_addr() * pdb.block_size());
        stream_map = pdb.get_mapping(
            file_data, block_map,
            std::ceil(pdb.num_directory_bytes() / static_cast<float>(pdb.block_size())));

        // Find the start of each stream directory
        std::map<uint32_t, const char*> stream_mapping_dir;
        const char* mapping_dir = reinterpret_cast<const char*>(
            stream_map->data() + sizeof(uint32_t) + (sizeof(uint32_t) * num_streams()));
        for (uint32_t i = 0; i < num_streams(); ++i) {
            stream_mapping_dir[i] = mapping_dir;
            uint32_t num_blocks =
                std::ceil(stream_length(i) / static_cast<float>(pdb.block_size()));
            mapping_dir += (sizeof(uint32_t) * num_blocks);
        }

        // DebugInfoStream
        auto debug_info_mapping = get_stream(pdb, file_data, 3, stream_mapping_dir.at(3));
        debug_info = std::make_unique<DebugInfoStream>(std::move(debug_info_mapping));

        // OMAPFromSourceStream (may not be present)
        const uint16_t omap_from_source_stream_id =
            debug_info->optional_debug_header().omap_from_src_stream();
        if (omap_from_source_stream_id < num_streams()) {
            auto omap_from_source_mapping =
                get_stream(pdb, file_data, omap_from_source_stream_id,
                           stream_mapping_dir.at(omap_from_source_stream_id));
            omap_from_source_stream =
                std::make_unique<OMAPFromSourceStream>(std::move(omap_from_source_mapping));
        }

        // SectionHeaderStream (may not be present)
        uint16_t section_header_stream_id =
            debug_info->optional_debug_header().section_hdr_orig_stream();
        if (section_header_stream_id == 0xFFFF) {
            section_header_stream_id = debug_info->optional_debug_header().section_hdr_stream();
        }
        if (section_header_stream_id < num_streams()) {
            auto section_headers_mapping =
                get_stream(pdb, file_data, section_header_stream_id,
                           stream_mapping_dir.at(section_header_stream_id));
            section_headers =
                std::make_unique<SectionHeaderStream>(std::move(section_headers_mapping));
        }

        // SymbolRecordStream
        auto sym_record_mapping =
            get_stream(pdb, file_data, debug_info->sym_record_stream(),
                       stream_mapping_dir.at(debug_info->sym_record_stream()));
        symbol_records = std::make_unique<SymbolRecordStream>(
            std::move(sym_record_mapping), section_headers.get(), omap_from_source_stream.get());

        // const TypeInfoStream& type_info_stream() const;
        auto type_info_mapping = get_stream(pdb, file_data, 2, stream_mapping_dir.at(2));
        type_info = std::make_unique<TypeInfoStream>(std::move(type_info_mapping));
    }

    uint32_t num_streams() const {
        const uint32_t* num_streams = reinterpret_cast<const uint32_t*>(stream_map->data());
        return le32toh(*num_streams);
    }

    uint32_t stream_length(uint32_t stream_id) const {
        if (unlikely(stream_id >= num_streams())) {
            throw std::out_of_range("stream_id out of range: " + std::to_string(stream_id));
        }
        const uint32_t* length_array =
            reinterpret_cast<const uint32_t*>(stream_map->data() + sizeof(uint32_t));
        return le32toh(length_array[stream_id]);
    }

    std::unique_ptr<const Mapping> get_stream(const PDB& pdb, const char* file_data,
                                              uint32_t stream_id, const char* mapping_dir) const {
        if (unlikely(stream_id >= num_streams())) {
            throw std::out_of_range("stream_id out of range: " + std::to_string(stream_id));
        }
        return pdb.get_mapping(
            file_data, mapping_dir,
            std::ceil(stream_length(stream_id) / static_cast<float>(pdb.block_size())));
    }

  public:
    std::unique_ptr<const Mapping> stream_map;
    std::unique_ptr<DebugInfoStream> debug_info;
    std::unique_ptr<OMAPFromSourceStream> omap_from_source_stream;
    std::unique_ptr<SectionHeaderStream> section_headers;
    std::unique_ptr<SymbolRecordStream> symbol_records;
    std::unique_ptr<TypeInfoStream> type_info;
};

const DebugInfoStream& StreamDirectory::debug_info_stream() const { return *(pImpl->debug_info); }
const OMAPFromSourceStream* StreamDirectory::omap_from_source_stream() const {
    return pImpl->omap_from_source_stream.get();
}
const SectionHeaderStream* StreamDirectory::section_header_stream() const {
    return pImpl->section_headers.get();
}
const SymbolRecordStream& StreamDirectory::symbol_record_stream() const {
    return *(pImpl->symbol_records);
}
const TypeInfoStream& StreamDirectory::type_info_stream() const { return *(pImpl->type_info); }

StreamDirectory::StreamDirectory(const PDB& pdb, const char* file_data)
    : pImpl(std::make_unique<IMPL>(pdb, file_data)) {}

StreamDirectory::~StreamDirectory() = default;

} /* namespace mspdb */
