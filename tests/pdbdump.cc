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

#include <iostream>

using namespace mspdb;
using namespace std;

int main() {
    PDB pdb("/home/papes/git/libmspdb/ntkrnlmp.pdb");

    cout << "BlockSize: " << pdb.block_size() << '\n';
    cout << "NumBlocks: " << pdb.num_blocks() << '\n';
    cout << "NumDirectoryBytes: " << pdb.num_directory_bytes() << '\n';

    auto& stream_dir = pdb.stream_directory();

    auto& debug_info = stream_dir.debug_info_stream();
    cout << "Version signature: 0x" << std::hex << debug_info.version_signature() << std::dec
         << '\n';
    cout << "Debug Version: 0x" << std::hex << debug_info.version_header() << std::dec << '\n';
    cout << "SymInfoStream: " << debug_info.sym_record_stream() << '\n';
    cout << "OMAPFromSourceStream: " << debug_info.optional_debug_header().omap_from_src_stream()
         << '\n';

    if (stream_dir.section_header_stream()) {
        cout << "Section Headers:\n";
        int i = 0;
        for (const auto& section : stream_dir.section_header_stream()->section_headers()) {
            cout << "[" << i++ << "]  Section: " << section.name() << '\n';
        }
    }

    cout << "Symbols: \n";
    std::cout << hex;
    for (auto& symbol : pdb.global_symbols()) {
        cout << "  " << symbol->name() << ": 0x" << symbol->image_offset()
             << " Code: " << symbol->code() << " Function: " << symbol->function() << "\n";
    }
    std::cout << dec;

    return 0;
}
