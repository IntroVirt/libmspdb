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

#include "DebugModuleInfo.hh"
#include "pdb_exception.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <cstring>

namespace mspdb {

struct SectionContribEntry {
    le_uint16_t Section;
    le_uint16_t Padding1;
    le_int32_t Offset;
    le_int32_t Size;
    le_uint32_t Characteristics;
    le_uint16_t ModuleIndex;
    le_uint16_t Padding2;
    le_uint32_t DataCrc;
    le_uint32_t RelocCrc;
};

struct ModInfo {
    le_uint32_t Unused1;
    SectionContribEntry SectionContr;
    le_uint16_t Flags;
    le_uint16_t ModuleSymStream;
    le_uint32_t SymByteSize;
    le_uint32_t C11ByteSize;
    le_uint32_t C13ByteSize;
    le_uint16_t SourceFileCount;
    le_uint16_t Padding;
    le_uint32_t Unused2;
    le_uint32_t SourceFileNameIndex;
    le_uint32_t PdbFilePathNameIndex;
};

class DebugModuleInfo::IMPL {
  public:
    IMPL(const char*& data, int32_t& buffer_len) {
        // +2 for at least two null terminators
        if (unlikely(buffer_len < sizeof(struct ModInfo) + 2)) {
            throw pdb_exception("Buffer underrun parsing ModInfo structure");
        }
        // Get the main header
        mod_info = *reinterpret_cast<const struct ModInfo*>(data);
        buffer_len -= sizeof(struct ModInfo);
        data += sizeof(struct ModInfo);

        // After the header are the strings
        const size_t module_name_len = strnlen(data, buffer_len);
        module_name = std::string(data, module_name_len);
        data += (module_name_len + 1);
        buffer_len -= (module_name_len + 1);

        if (unlikely(buffer_len) < 0)
            throw pdb_exception("Buffer underrun parsing ModInfo::ModuleName");

        const size_t obj_filename_len = strnlen(data, buffer_len);
        obj_filename = std::string(data, obj_filename_len);
        data += (obj_filename_len + 1);
        buffer_len -= (obj_filename_len + 1);
        if (unlikely(buffer_len) < 0)
            throw pdb_exception("Buffer underrun parsing ModInfo::ObjFileName");

        const uint32_t size =
            sizeof(ModInfo) + (module_name.length() + 1) + (obj_filename.length() + 1);

        // We need to align the size to 4 bytes
        // Calculate the next aligned value (may be the value itself)
        const unsigned int next_multiple = ((size + 3) / 4) * 4;

        // Figure out how much padding we need
        const unsigned int padding = next_multiple - size;

        data += padding;
        buffer_len -= padding;
    }

  public:
    std::string module_name;
    std::string obj_filename;
    struct ModInfo mod_info;
};

uint16_t DebugModuleInfo::section() const { return pImpl->mod_info.SectionContr.Section; }
int32_t DebugModuleInfo::offset() const { return pImpl->mod_info.SectionContr.Offset; }
int32_t DebugModuleInfo::size() const { return pImpl->mod_info.SectionContr.Size; }
uint16_t DebugModuleInfo::module_index() const { return pImpl->mod_info.SectionContr.ModuleIndex; }
uint32_t DebugModuleInfo::module_sym_stream() const { return pImpl->mod_info.ModuleSymStream; }
uint32_t DebugModuleInfo::sym_byte_size() const { return pImpl->mod_info.SymByteSize; }
uint16_t DebugModuleInfo::source_file_count() const { return pImpl->mod_info.SourceFileCount; }

const std::string& DebugModuleInfo::module_name() const { return pImpl->module_name; }
const std::string& DebugModuleInfo::obj_filename() const { return pImpl->obj_filename; }

DebugModuleInfo::DebugModuleInfo(const char*& data, int32_t& buffer_len)
    : pImpl(std::make_unique<IMPL>(data, buffer_len)) {}
DebugModuleInfo::DebugModuleInfo(DebugModuleInfo&&) noexcept = default;
DebugModuleInfo& DebugModuleInfo::operator=(DebugModuleInfo&&) noexcept = default;
DebugModuleInfo::~DebugModuleInfo() = default;

} /* namespace mspdb */
