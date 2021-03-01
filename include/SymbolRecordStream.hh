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
#ifndef LIBPDB_SYMBOL_RECORD_STREAM_HH_
#define LIBPDB_SYMBOL_RECORD_STREAM_HH_

#include "DebugModuleInfo.hh"

#include <cstdint>
#include <memory>
#include <vector>

namespace mspdb {

class Mapping;
class OMAPFromSourceStream;
class SectionHeaderStream;

class Symbol {
  public:
    virtual uint32_t flags() const = 0;

    virtual bool code() const = 0;
    virtual bool function() const = 0;
    virtual bool managed() const = 0;
    virtual bool msil() const = 0;

    virtual const std::string& name() const = 0;
    virtual int32_t image_offset() const = 0;
    virtual uint16_t segment() const = 0;
    virtual uint16_t type() const = 0;

    virtual ~Symbol() = default;
};

class SymbolRecordStream {
  public:
    SymbolRecordStream(std::unique_ptr<const Mapping>&& mapping,
                       const SectionHeaderStream* section_header_stream,
                       const OMAPFromSourceStream* omap);
    SymbolRecordStream(SymbolRecordStream&&) noexcept;
    SymbolRecordStream& operator=(SymbolRecordStream&&) noexcept;
    ~SymbolRecordStream();

  public:
    const std::vector<std::unique_ptr<Symbol>>& symbols() const;

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl;
};

} /* namespace mspdb */

#endif /* LIBPDB_SYMBOL_RECORD_STREAM_HH_ */