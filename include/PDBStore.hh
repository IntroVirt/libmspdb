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
#ifndef LIBPDB_PDBSTORE_HH_
#define LIBPDB_PDBSTORE_HH_

#include "PDB.hh"

#include <memory>
#include <string>

namespace mspdb {

/**
 * @brief Storage and retrieval for Microsoft PDBs
 */
class PDBStore {
  public:
    /**
     * @brief Create a new PDBStore
     * @param symbol_store_dir The path to use for storage
     *
     * This will use the default Microsoft symbol server URL.
     */
    PDBStore(const std::string& symbol_store_dir);

    /**
     * @brief Create a new PDBStore
     * @param symbol_store_dir The path to use for storage
     * @param symbol_server_url The symbol server URL to use
     */
    PDBStore(const std::string& symbol_store_dir, const std::string& symbol_server_url);

    ~PDBStore();

  public:
    /**
     * @brief Load a PDB file
     *
     * This method will try to load a file from disk. Failing that, it will attempt to download it
     * from the symbol server.
     *
     * @param pdb_filename The filename to load
     * @param pdb_identifier The PDBs unique identifier
     */
    std::unique_ptr<PDB> open_pdb(const std::string& pdb_filename,
                                  const std::string& pdb_identifier);

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} // namespace mspdb

#endif /* LIBPDB_PDBSTORE_HH_ */