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
#ifndef LIBPDB_STREAM_DIRECTORY_HH
#define LIBPDB_STREAM_DIRECTORY_HH

#include "DebugInfoStream.hh"
#include "OMAPFromSourceStream.hh"
#include "SectionHeaderStream.hh"
#include "SymbolRecordStream.hh"
#include "TypeInfoStream.hh"

#include <cstdint>
#include <memory>

namespace mspdb {

class PDB;

class StreamDirectory {
  public:
    StreamDirectory(const PDB& pdb, const char* file_data);
    ~StreamDirectory();

  public:
    const DebugInfoStream& debug_info_stream() const;
    const OMAPFromSourceStream* omap_from_source_stream() const;
    const SectionHeaderStream* section_header_stream() const;
    const SymbolRecordStream& symbol_record_stream() const;
    const TypeInfoStream& type_info_stream() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_STREAM_DIRECTORY_HH */