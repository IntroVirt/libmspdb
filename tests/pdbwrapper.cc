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
#include "pdb_exception.hh"

#include <functional>
#include <iomanip>
#include <iostream>
#include <map>

using namespace mspdb;
using namespace std;

std::string get_type(const LF_TYPE& lfType) {
    switch (lfType.type()) {
    case LEAF_TYPE::LF_MODIFIER:
        // Don't care about these, just recurse.
        return get_type(static_cast<const LF_MODIFIER&>(lfType).modified_type());
    case LEAF_TYPE::LF_POINTER:
        return "PtrType";
    case LEAF_TYPE::LF_BUILTIN:
        return to_string(static_cast<const LF_BUILTIN&>(lfType).builtin_type());
    case LEAF_TYPE::LF_CLASS:
    case LEAF_TYPE::LF_STRUCTURE:
        return static_cast<const LF_STRUCTURE&>(lfType).name();
    case LEAF_TYPE::LF_BITFIELD:
        return get_type(static_cast<const LF_BITFIELD&>(lfType).base_type());
    case LEAF_TYPE::LF_ARRAY:
        return get_type(static_cast<const LF_ARRAY&>(lfType).element_type());
    default:
        throw pdb_exception("Unhandled type: " + to_string(lfType.type()));
    }
}

template <typename T>
void write_wrapper(const T& lfStruct) {
    std::cout << "class " << lfStruct.name() << " {\n";
    std::cout << "public:\n";

    for (const LF_MEMBER& member : lfStruct.field_list()) {
        std::cout << "    virtual " << get_type(member.index()) << " " << member.name() << "() {\n";
        std::cout << std::hex;
        switch (member.index().type()) {
        default:
            std::cout << "        return *reinterpret_cast<const " << get_type(member.index())
                      << "*>(buffer + 0x" << member.offset() << ");\n";
        }
        std::cout << std::dec;
        std::cout << "    };\n";
    }

    std::cout << "};\n";
}

int main() {
    PDB pdb("/Users/papes/git/libmspdb/ntkrnlmp.pdb");
    const auto& tpi = pdb.stream_directory().type_info_stream();

    for (const LF_STRUCTURE& lfStruct : tpi.structs()) {
        if (lfStruct.fwdref() || lfStruct.name() == "<unnamed-tag>")
            continue;
        if (lfStruct.name() != "_EPROCESS")
            continue;

        write_wrapper(lfStruct);
    }

    return 0;
}
