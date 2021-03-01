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
#ifndef LIBPDB_PDB_HH_
#define LIBPDB_PDB_HH_

#include "StreamDirectory.hh"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

namespace mspdb {

class Mapping;

class PDB {
  public:
    PDB(const std::string& path);
    ~PDB();

  public:
    // PDB header information
    uint32_t block_size() const;
    uint32_t num_blocks() const;
    uint32_t num_directory_bytes() const;
    uint32_t block_map_addr() const;

  public:
    /**
     * @brief Look up a symbol name given a relative virtual address
     * @param rva The relative virtual address of the symbol to match
     * @returns the symbol at the given offset, or nullptr if not found
     */
    const Symbol* rva_to_symbol(uint32_t rva) const;
    /**
     * @brief Look up a symbol by name
     * @param symbol The name of the symbol to match (case insensitive)
     * @returns the matching symbol, or nullptr if not found
     */
    const Symbol* name_to_symbol(const std::string& symbol) const;

    const std::vector<std::unique_ptr<Symbol>>& global_symbols() const;

    /**
     * @returns The LF_CLASS/LF_STRUCTURE/LF_UNION, or nullptr if not found
     */
    const LF_FIELDLIST_CONTAINER* find_struct(const std::string& name) const;

  public:
    uint32_t block_offset(uint32_t block_id) const;
    const StreamDirectory& stream_directory() const;
    std::unique_ptr<const Mapping> get_mapping(const char* file_data, const char* block_map,
                                               uint32_t num_blocks) const;

  public:
    PDB(PDB&&) noexcept;
    PDB& operator=(PDB&&) noexcept;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_PDB_HH_ */