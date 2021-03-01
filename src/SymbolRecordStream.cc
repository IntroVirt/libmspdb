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

#include "SymbolRecordStream.hh"
#include "Mapping.hh"
#include "OMAPFromSourceStream.hh"
#include "SectionHeaderStream.hh"

#include "builtin_expect.hh"
#include "portable_endian.hh"

#include <cstring>
#include <string>

namespace mspdb {

static const uint16_t S_PUB32 = 0x0000110E;

struct _SYM {
    le_uint16_t reclen;
    le_uint16_t rectyp;
};

enum _PUBSYMFLAGS {
    None = 0x00000000,
    Code = 0x00000001,
    Function = 0x00000002,
    Managed = 0x00000004,
    MSIL = 0x00000008,
};

struct _PUBSYM32 : public _SYM {
    le_uint32_t pubsymflags;
    le_int32_t off;
    le_uint16_t seg;
    char name[];
};

// Used to normalize symbol names
static std::string normalize(std::string_view view) {
    if (view[0] == '_') {
        // x86 symbols start with a _, but x64 don't. Strip it to normalize.
        view = view.substr(1);
    }

    // x86 symbols can end with something like "@24"
    auto pos = view.rfind("@");
    if (pos != std::string::npos && pos >= (view.size() - 3))
        view = view.substr(0, pos);

    return std::string(view);
}

class PUBSYM32 final : public Symbol {
  public:
    PUBSYM32(const _PUBSYM32* sym, size_t buffer_len,
             const std::vector<ImageSectionHeader>* section_headers,
             const OMAPFromSourceStream* omap)
        : symname(normalize(std::string(sym->name, strnlen(sym->name, buffer_len)))), sym(*sym) {

        if (section_headers) {
            section_base = section_headers->at(segment() - 1).virtual_address();

            if (omap) {
                // TODO: Verify this is right, haven't actually seen a PDB with OMAP information
                const OMAPEntry entry = omap->find(image_offset());
                omap_offset = entry.sourceRVA() + entry.destRVA();
            }
        }
    }

  public:
    uint32_t flags() const override { return sym.pubsymflags; }
    bool code() const { return flags() & _PUBSYMFLAGS::Code; }
    bool function() const { return flags() & _PUBSYMFLAGS::Function; }
    bool managed() const { return flags() & _PUBSYMFLAGS::Managed; }
    bool msil() const { return flags() & _PUBSYMFLAGS::MSIL; }

    const std::string& name() const override { return symname; }
    int32_t image_offset() const override { return section_base + sym.off - omap_offset; }
    uint16_t segment() const override { return sym.seg; }
    uint16_t type() const override { return sym.rectyp; }

  private:
    const std::string symname;
    uint64_t section_base = 0;
    uint64_t omap_offset = 0;
    const struct _PUBSYM32 sym;
};

class SymbolRecordStream::IMPL {
  public:
    IMPL(std::unique_ptr<const Mapping>&& stream_mapping,
         const SectionHeaderStream* section_header_stream, const OMAPFromSourceStream* omap) {
        const char* ptr = reinterpret_cast<const char*>(stream_mapping->data());
        const char* end = ptr + stream_mapping->length();

        const std::vector<ImageSectionHeader>* section_headers = nullptr;
        if (section_header_stream)
            section_headers = &(section_header_stream->section_headers());

        while (ptr < end) {
            const _SYM* sym = reinterpret_cast<const _SYM*>(ptr);
            if (unlikely(sym->reclen < sizeof(uint16_t))) {
                // Not enough room for the type field, what?
                // Just advance to the next symbol.
                ptr += sizeof(uint16_t);
                continue;
            }

            switch (sym->rectyp) {
            case 0:
                return; // Done!
            case S_PUB32: {
                const _PUBSYM32* pubsym = reinterpret_cast<const _PUBSYM32*>(sym);
                symbols.push_back(std::make_unique<PUBSYM32>(pubsym, static_cast<size_t>(end - ptr),
                                                             section_headers, omap));
                break;
            }
            }

            // Advance to the next symbol
            ptr += sizeof(uint16_t) + sym->reclen;
        }
    }

  public:
    std::vector<std::unique_ptr<Symbol>> symbols;
};

const std::vector<std::unique_ptr<Symbol>>& SymbolRecordStream::symbols() const {
    return pImpl->symbols;
}

SymbolRecordStream::SymbolRecordStream(std::unique_ptr<const Mapping>&& mapping,
                                       const SectionHeaderStream* section_header_stream,
                                       const OMAPFromSourceStream* omap)
    : pImpl(std::make_unique<IMPL>(std::move(mapping), section_header_stream, omap)) {}

SymbolRecordStream::SymbolRecordStream(SymbolRecordStream&&) noexcept = default;
SymbolRecordStream& SymbolRecordStream::operator=(SymbolRecordStream&&) noexcept = default;
SymbolRecordStream::~SymbolRecordStream() = default;

} /* namespace mspdb */
