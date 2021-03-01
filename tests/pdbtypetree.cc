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

void recurse(const LF_TYPE& type, const std::string& prefix = "") {
    std::cout << to_string(type.type());

    switch (type.type()) {
    case LEAF_TYPE::LF_ARRAY:
        std::cout << "->";
        recurse(static_cast<const LF_ARRAY&>(type).element_type(), prefix);
        return;
    case LEAF_TYPE::LF_BITFIELD:
        std::cout << "->";
        recurse(static_cast<const LF_BITFIELD&>(type).base_type(), prefix);
        return;
    case LEAF_TYPE::LF_MEMBER:
        std::cout << "->";
        recurse(static_cast<const LF_MEMBER&>(type).index(), prefix);
        return;
    case LEAF_TYPE::LF_MODIFIER: {
        const auto& lfModifier = static_cast<const LF_MODIFIER&>(type);
        std::cout << std::hex;
        std::cout << "(0x" << lfModifier.modifiers() << ")->";
        std::cout << std::dec;
        recurse(lfModifier.modified_type(), prefix);
        return;
    }
    case LEAF_TYPE::LF_POINTER: {
        const auto& lfPointer = static_cast<const LF_POINTER&>(type);
        std::cout << std::hex;
        std::cout << "(0x" << lfPointer.size() << ")->";
        std::cout << std::dec;
        recurse(lfPointer.underlying_type(), prefix);
        return;
    }
    case LEAF_TYPE::LF_PROCEDURE: {
        std::cout << '\n';
        const auto& lfProc = static_cast<const LF_PROCEDURE&>(type);
        const std::string new_prefix = prefix + "    ";
        for (const LF_TYPE& member : lfProc.arg_list()) {
            std::cout << new_prefix;
            recurse(member, new_prefix);
        }
        return;
    }
    case LEAF_TYPE::LF_CLASS:
    case LEAF_TYPE::LF_STRUCTURE: {
        const auto& lfStruct = static_cast<const LF_STRUCTURE&>(type);
        std::cout << "(" << lfStruct.name() << ")\n";
        if (!lfStruct.fwdref()) {
            const std::string new_prefix = prefix + "    ";
            for (const LF_MEMBER& member : lfStruct.field_list()) {
                std::cout << new_prefix;
                recurse(member, new_prefix);
            }
        }
        return;
    }
    case LEAF_TYPE::LF_UNION: {
        const auto& lfStruct = static_cast<const LF_UNION&>(type);
        std::cout << "(" << lfStruct.name() << ")\n";
        if (!lfStruct.fwdref()) {
            const std::string new_prefix = prefix + "    ";
            for (const LF_MEMBER& member : lfStruct.field_list()) {
                std::cout << new_prefix;
                recurse(member, new_prefix);
            }
        }
        return;
    }
    default:
        break;
    }

    std::cout << "\n";
}

int main() {
    PDB pdb("/home/papes/git/libmspdb/ntkrnlmp.pdb");
    const auto& tpi = pdb.stream_directory().type_info_stream();

    for (const LF_CLASS& entry : tpi.classes()) {
        recurse(entry);
    }
    for (const LF_STRUCTURE& entry : tpi.structs()) {
        recurse(entry);
    }

    for (const LF_UNION& entry : tpi.unions()) {
        recurse(entry);
    }

    return 0;
}
