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
#include <vector>

using namespace mspdb;

// Used to prevent infinity. If the thing we're about to recurse into is already
// in the stack of things we're recursed into, then we don't want to do that.
static std::vector<const LF_TYPE*> type_stack;

void recurse(const LF_TYPE& type, const std::string& prefix = "") {
    if (std::find(type_stack.begin(), type_stack.end(), &type) == type_stack.end()) {
        type_stack.push_back(&type);
    } else {
        std::cout << to_string(type.type()) <<"(stopping here - infinite recursive type)\n";
        return;
    }
    std::cout << to_string(type.type());

    switch (type.type()) {
    case LEAF_TYPE::LF_ARRAY:
        std::cout << "->";
        recurse(static_cast<const LF_ARRAY&>(type).element_type(), prefix);
        type_stack.pop_back();
        return;
    case LEAF_TYPE::LF_BITFIELD:
        std::cout << "->";
        recurse(static_cast<const LF_BITFIELD&>(type).base_type(), prefix);
        type_stack.pop_back();
        return;
    case LEAF_TYPE::LF_MEMBER:
        std::cout << "->";
        recurse(static_cast<const LF_MEMBER&>(type).index(), prefix);
        type_stack.pop_back();
        return;
    case LEAF_TYPE::LF_MODIFIER: {
        const auto& lfModifier = static_cast<const LF_MODIFIER&>(type);
        std::cout << std::hex;
        std::cout << "(0x" << lfModifier.modifiers() << ")->";
        std::cout << std::dec;

        const auto& lfType = lfModifier.modified_type();
        if (std::find(type_stack.begin(), type_stack.end(), &lfType) == type_stack.end()) {
            type_stack.push_back(&lfType);
        } else {
            std::cout << to_string(type.type()) <<"(stopping here - infinite recursive modifier)\n";
            return;
        }

        recurse(lfType, prefix);
        type_stack.pop_back();
        return;
    }
    case LEAF_TYPE::LF_POINTER: {
        const auto& lfPointer = static_cast<const LF_POINTER&>(type);

        std::cout << std::hex;
        std::cout << "(0x" << lfPointer.size() << ")->";
        std::cout << std::dec;

        const auto& lfType = lfPointer.underlying_type();
        if (std::find(type_stack.begin(), type_stack.end(), &lfType) == type_stack.end()) {
            type_stack.push_back(&lfType);
        } else {
            std::cout << to_string(type.type()) <<"(stopping here - infinite recursive pointer)\n";
            return;
        }
        recurse(lfType, prefix);
        type_stack.pop_back();
        return;
    }
    case LEAF_TYPE::LF_PROCEDURE: {
        std::cout << '\n';
        const auto& lfProc = static_cast<const LF_PROCEDURE&>(type);
        const std::string new_prefix = prefix + "    ";
        for (const LF_TYPE& member : lfProc.arg_list()) {
            std::cout << new_prefix;
            recurse(member, new_prefix);
            type_stack.pop_back();
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
                type_stack.pop_back();
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
                type_stack.pop_back();
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
    PDB pdb("./pdbstore/ntdll.pdb/08A413EE85E91D0377BA33DC3A2641941/ntdll.pdb");
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
