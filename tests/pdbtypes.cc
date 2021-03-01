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

class TypeContainer {
  protected:
    TypeContainer(const TypeInfoStream& tpi, int level) : tpi(tpi), level(level) {}

    void write_member(const LF_MEMBER& lfMember) const;

    void indent() const {
        for (int i = 0; i < level; ++i) {
            std::cout << "    ";
        }
    }

    void level_up() const { ++level; }
    void level_down() const { --level; }
    virtual void write() const = 0;

  protected:
    const TypeInfoStream& tpi;
    mutable int level;
    const LF_MODIFIER* modifier{nullptr};
    const std::vector<std::reference_wrapper<const LF_POINTER>>* pointers{nullptr};
    mutable bool in_bitfield = false;
};

class Structure : public TypeContainer {
  public:
    Structure(const TypeInfoStream& tpi, const LF_MEMBER& lfMember, int level)
        : Structure(tpi, static_cast<const LF_STRUCTURE&>(lfMember.index()), level) {

        this->name = lfMember.name();
        // this->modifier = lfMember.modifier();
        // this->pointers = &lfMember.pointers();
    }
    Structure(const TypeInfoStream& tpi, const LF_STRUCTURE& lfStructure, int level = 0)
        : TypeContainer(tpi, level), lfStructure(lfStructure) {

        if (!lfStructure.fwdref()) {
            for (const LF_MEMBER& lfMember : lfStructure.field_list()) {
                offset_to_members[lfMember.offset()].emplace_back(lfMember);
            }
        }
    }

  public:
    void write() const override {
        indent();

        if (modifier) {
            if (modifier->isconst())
                std::cout << "const ";
            if (modifier->isvolatile())
                std::cout << "volatile ";
        }

        if (pointers && !pointers->empty()) {
            std::cout << lfStructure.name();
            for (const LF_POINTER& pointer : *pointers) {
                std::cout << '*';
            }
            std::cout << ' ' << name << ";\n";
            return;
        }

        std::cout << "struct";
        if (lfStructure.name() != "<unnamed-tag>")
            std::cout << ' ' << lfStructure.name();

        std::cout << " {\n";
        level_up();
        for (const auto& iter : offset_to_members) {
            const auto& offset = iter.first;
            const auto& members = iter.second;
            if (members.size() > 1) {
                indent();
                std::cout << "union {\n";
                level_up();
            }
            for (const auto& member : members) {
                write_member(member);
            }
            if (members.size() > 1) {
                level_down();
                indent();
                std::cout << "};\n";
            }
        }
        level_down();
        indent();
        std::cout << "}";
        if (!lfStructure.fwdref() && !name.empty()) {
            std::cout << ' ' << name;
        }
        std::cout << ";\n";
    }

  private:
    const LF_STRUCTURE& lfStructure;
    std::string name;
    std::map<uint32_t, std::vector<std::reference_wrapper<const LF_MEMBER>>> offset_to_members;
};

class Union : public TypeContainer {
  public:
    Union(const TypeInfoStream& tpi, const LF_MEMBER& lfMember, int level)
        : Union(tpi, static_cast<const LF_UNION&>(lfMember.index()), level) {

        this->name = lfMember.name();
        // this->modifier = lfMember.modifier();
        // this->pointers = &lfMember.pointers();
    }
    Union(const TypeInfoStream& tpi, const LF_UNION& lfUnion, int level = 0)
        : TypeContainer(tpi, level), lfUnion(lfUnion) {

        if (!lfUnion.fwdref()) {
            for (const LF_MEMBER& lfMember : lfUnion.field_list()) {
                members.emplace_back(lfMember);
            }
        }
    }

  public:
    void write() const override {
        indent();

        if (modifier) {
            if (modifier->isconst())
                std::cout << "const ";
            if (modifier->isvolatile())
                std::cout << "volatile ";
        }
        /*
                if (pointers && !pointers->empty()) {
                    std::cout << lfUnion.name();
                    for(const LF_POINTER& pointer : *pointers) {
                        std::cout << '*';
                    }
                    std::cout << ' ' << name << ";\n";
                    return;
                }
        */

        std::cout << "union";
        if (lfUnion.name() != "<unnamed-tag>")
            std::cout << ' ' << lfUnion.name();

        std::cout << " {\n";
        level_up();

        for (const auto& member : members) {
            write_member(member);
        }

        level_down();
        indent();
        std::cout << "}";
        if (!name.empty()) {
            std::cout << ' ' << name;
        }
        std::cout << ";\n";
    }

  private:
    const LF_UNION& lfUnion;
    std::string name;
    std::vector<std::reference_wrapper<const LF_MEMBER>> members;
};

void TypeContainer::write_member(const LF_MEMBER& lfMember) const {

    if (lfMember.index().type() == LEAF_TYPE::LF_BITFIELD) {
        if (!in_bitfield) {
            indent();
            std::cout << "struct {\n";
            level_up();
            in_bitfield = true;
        }
    } else {
        if (in_bitfield) {
            level_down();
            indent();
            std::cout << "};\n";
            in_bitfield = false;
        }
    }

    switch (lfMember.index().type()) {
    case LEAF_TYPE::LF_BUILTIN:
        indent();
        /*
        if (lfMember.modifier()) {
            if(lfMember.modifier()->isconst()) {
                std::cout << "const ";
            }
            if(lfMember.modifier()->isvolatile()) {
                std::cout << "volatile ";
            }
        }
        */
        std::cout << to_string(static_cast<const LF_BUILTIN&>(lfMember.index()).builtin_type());
        // Handle pointers
        /*
        for (const LF_POINTER& ptr : lfMember.pointers()) {
            std::cout << "*";
            if (ptr.isconst())
                std::cout << " const";
        }
        */
        std::cout << ' ' << lfMember.name() << ";\n";
        break;
    case LEAF_TYPE::LF_ENUM:
        indent();
        std::cout << static_cast<const LF_ENUM&>(lfMember.index()).name() << ' ' << lfMember.name()
                  << ";\n";
        break;
    case LEAF_TYPE::LF_STRUCTURE: {
        Structure s(tpi, lfMember, level);
        s.write();
        break;
    }
    case LEAF_TYPE::LF_UNION: {
        Union u(tpi, lfMember, level);
        u.write();
        break;
    }
    case LEAF_TYPE::LF_BITFIELD: {
        indent();
        const auto& lfBitfield = static_cast<const LF_BITFIELD&>(lfMember.index());

        const LF_TYPE* base_type = &(lfBitfield.base_type());
        const LF_MODIFIER* lfModifier = nullptr;

        if (base_type->type() == LEAF_TYPE::LF_MODIFIER) {
            lfModifier = static_cast<const LF_MODIFIER*>(base_type);
            base_type = &(lfModifier->modified_type());
        }

        if (lfModifier != nullptr) {
            if (lfModifier->isconst())
                std::cout << "const ";
            if (lfModifier->isvolatile())
                std::cout << "volatile ";
        }

        if (base_type->type() == LEAF_TYPE::LF_ENUM) {
            const auto* lfEnum = static_cast<const LF_ENUM*>(base_type);
            std::cout << lfEnum->name();
        } else {
            if (base_type->type() != LEAF_TYPE::LF_BUILTIN) {
                throw pdb_exception("Non builtin base type for LF_BITFIELD: " +
                                    to_string(lfBitfield.base_type().type()));
            }
            const auto& lfBuiltin = static_cast<const LF_BUILTIN&>(*base_type);
            std::cout << to_string(lfBuiltin.builtin_type());
        }

        std::cout << ' ' << lfMember.name() << ": " << lfBitfield.length() << ";\n";

        break;
    }
    default:
        indent();
        std::cout << "UNHANDLED " << to_string(lfMember.index().type()) << '\n';
        break;
    }
}

int main() {
    PDB pdb("/home/papes/git/libmspdb/ntkrnlmp.pdb");
    const auto& tpi = pdb.stream_directory().type_info_stream();

    for (const LF_STRUCTURE& lfStruct : tpi.structs()) {
        if (lfStruct.fwdref() || lfStruct.name() == "<unnamed-tag>")
            continue;
        Structure s(tpi, lfStruct);
        s.write();
    }

    for (const LF_UNION& lfUnion : tpi.unions()) {
        if (lfUnion.fwdref() || lfUnion.name() == "<unnamed-tag>")
            continue;
        Union u(tpi, lfUnion);
        u.write();
    }

    return 0;
}
