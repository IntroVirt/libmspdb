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

#include "PDB.hh"

#include "Mapping.hh"
#include "StreamDirectory.hh"

#include "file_exception.hh"
#include "pdb_exception.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <boost/algorithm/string.hpp>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>

namespace mspdb {

static const char Magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\x0\x0\x0";
static const unsigned int MagicSize = sizeof(Magic) - 1; // Skip the string's null terminator

struct SuperBlock {
    char FileMagic[MagicSize];
    le_uint32_t BlockSize;
    le_uint32_t FreeBlockMapBlock;
    le_uint32_t NumBlocks;
    le_uint32_t NumDirectoryBytes;
    le_uint32_t Unknown;
    le_uint32_t BlockMapAddr;
};

class PDB::IMPL {
  public:
    inline uint32_t block_size() const { return le32toh(super_block.BlockSize); }
    inline uint32_t free_block_map_block() const { return le32toh(super_block.FreeBlockMapBlock); }
    inline uint32_t num_blocks() const { return le32toh(super_block.NumBlocks); }
    inline uint32_t num_directory_bytes() const { return le32toh(super_block.NumDirectoryBytes); }
    inline uint32_t block_map_addr() const { return le32toh(super_block.BlockMapAddr); }

  public:
    uint32_t block_offset(uint32_t block_id) const {
        uint32_t result = block_size() * block_id;
        if (unlikely((result + block_size()) > file_size)) {
            throw std::out_of_range("block_offset past end of file: " + std::to_string(block_id));
        }
        return result;
    }

  public:
    struct SuperBlock super_block;
    std::unique_ptr<StreamDirectory> stream_directory;
    size_t file_size{0};

    std::unordered_map<std::string, Symbol*> name_to_symbol;
    std::unordered_map<uint32_t, Symbol*> rva_to_symbol;

    std::unordered_map<std::string, std::reference_wrapper<const LF_FIELDLIST_CONTAINER>>
        name_to_structure;
};

const Symbol* PDB::rva_to_symbol(uint32_t rva) const {
    auto it = pImpl->rva_to_symbol.find(rva);
    if (it != pImpl->rva_to_symbol.end())
        return it->second;

    return nullptr;
}
const Symbol* PDB::name_to_symbol(const std::string& symbol) const {
    std::string lower_name = symbol;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    const auto it = pImpl->name_to_symbol.find(lower_name);
    if (it != pImpl->name_to_symbol.end())
        return it->second;

    return nullptr;
}

const std::vector<std::unique_ptr<Symbol>>& PDB::global_symbols() const {
    return pImpl->stream_directory->symbol_record_stream().symbols();
}

const LF_FIELDLIST_CONTAINER* PDB::find_struct(const std::string& name) const {
    auto iter = pImpl->name_to_structure.find(name);
    if (iter != pImpl->name_to_structure.end()) {
        return &(iter->second.get());
    }
    return nullptr;
}

PDB::PDB(const std::string& path) : pImpl(std::make_unique<IMPL>()) {

    const int fd = open(path.c_str(), O_RDONLY, 0);
    if (unlikely(fd < 0)) {
        throw file_exception("Failed to open file " + path, errno);
    }

    struct stat st;
    if (unlikely(fstat(fd, &st))) {
        close(fd);
        throw file_exception("Failed to fstat file " + path, errno);
    }
    pImpl->file_size = st.st_size;

    // Lambda so we can use mmap with unique_ptr
    // Our mapped file will automatically be released at the end of the constructor
    auto unmapper = [st](void* p) {
        if (p != MAP_FAILED)
            munmap(p, st.st_size);
    };
    std::unique_ptr<void, decltype(unmapper)> mapped_file(
        mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0), unmapper);
    if (unlikely(mapped_file.get() == MAP_FAILED)) {
        close(fd);
        throw file_exception("Failed to map file " + path, errno);
    }
    const char* file_data = reinterpret_cast<const char*>(mapped_file.get());

    // File is memory mapped, we don't need this anymore
    close(fd);

    // Copy the superblock
    pImpl->super_block = *reinterpret_cast<const SuperBlock*>(file_data);
    if (unlikely(std::memcmp(pImpl->super_block.FileMagic, Magic, MagicSize) != 0)) {
        throw pdb_exception("Invalid magic");
    }

    // Create our stream directory
    pImpl->stream_directory = std::make_unique<StreamDirectory>(*this, file_data);

    const std::vector<ImageSectionHeader>* section_headers = nullptr;
    if (pImpl->stream_directory->section_header_stream())
        section_headers = &(pImpl->stream_directory->section_header_stream()->section_headers());

    // Parse our symbols
    const auto& symbols = pImpl->stream_directory->symbol_record_stream().symbols();
    for (const auto& symbol : symbols) {
        // Get the symbol's self reported offset
        const uint32_t rva = symbol->image_offset();

        if (!symbol->name().empty()) {
            const std::string symbol_name(boost::to_lower_copy(symbol->name()));
            pImpl->name_to_symbol[symbol_name] = symbol.get();
        }

        pImpl->rva_to_symbol[rva] = symbol.get();
    }

    // Parse our types
    for (const LF_FIELDLIST_CONTAINER& lfStructure :
         pImpl->stream_directory->type_info_stream().structs()) {
        if (!lfStructure.fwdref()) {
            auto [iter, inserted] =
                pImpl->name_to_structure.try_emplace(lfStructure.name(), std::ref(lfStructure));

            // Overwrite the old one if it exists
            if (!inserted)
                iter->second = std::ref(lfStructure);
        }
    }
    for (const LF_FIELDLIST_CONTAINER& lfStructure :
         pImpl->stream_directory->type_info_stream().classes()) {
        if (!lfStructure.fwdref()) {
            pImpl->name_to_structure.try_emplace(lfStructure.name(), std::ref(lfStructure));
        }
    }
    for (const LF_FIELDLIST_CONTAINER& lfStructure :
         pImpl->stream_directory->type_info_stream().unions()) {
        if (!lfStructure.fwdref()) {
            pImpl->name_to_structure.try_emplace(lfStructure.name(), std::ref(lfStructure));
        }
    }
}

uint32_t PDB::block_size() const { return pImpl->block_size(); }
uint32_t PDB::num_blocks() const { return pImpl->num_blocks(); }
uint32_t PDB::num_directory_bytes() const { return pImpl->num_directory_bytes(); }
uint32_t PDB::block_map_addr() const { return pImpl->block_map_addr(); }

uint32_t PDB::block_offset(uint32_t block_id) const { return pImpl->block_offset(block_id); }

const StreamDirectory& PDB::stream_directory() const { return *pImpl->stream_directory; }

std::unique_ptr<const Mapping> PDB::get_mapping(const char* file_data, const char* block_map,
                                                uint32_t num_blocks) const {
    const uint32_t length = block_size() * num_blocks;
    auto result = std::make_unique<Mapping>(length);

    const uint32_t* stream_dir_blocks = reinterpret_cast<const uint32_t*>(block_map);
    for (uint32_t i = 0; i < num_blocks; ++i) {
        const char* const source_block = file_data + block_offset(stream_dir_blocks[i]);
        std::copy_n(source_block, block_size(), result->data() + (i * block_size()));
    }

    return result;
}

PDB::~PDB() = default;
PDB::PDB(PDB&&) noexcept = default;
PDB& PDB::operator=(PDB&&) noexcept = default;

} // namespace mspdb
