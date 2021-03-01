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
#ifndef LIBPDB_TYPE_INFO_CV_PROPERTY_HH_
#define LIBPDB_TYPE_INFO_CV_PROPERTY_HH_

#include "../portable_endian.hh"
#include <cstdint>

namespace mspdb {

class CV_Property {
  public:
    inline bool packed() const { return property & PACKED_MASK; }
    inline bool ctor() const { return property & CTOR_MASK; }
    inline bool ovlops() const { return property & OVLOPS_MASK; }
    inline bool nested() const { return property & NESTED_MASK; }
    inline bool cnested() const { return property & CNESTED_MASK; }
    inline bool opassign() const { return property & OPASSIGN_MASK; }
    inline bool opcast() const { return property & OPCAST_MASK; }
    inline bool fwdref() const { return property & FWDREF_MASK; }
    inline bool scoped() const { return property & SCOPED_MASK; }
    inline uint16_t raw() const { return property; }

  private:
    static const uint16_t PACKED_MASK = (1u << 0);
    static const uint16_t CTOR_MASK = (1u << 1);
    static const uint16_t OVLOPS_MASK = (1u << 2);
    static const uint16_t NESTED_MASK = (1u << 3);
    static const uint16_t CNESTED_MASK = (1u << 4);
    static const uint16_t OPASSIGN_MASK = (1u << 5);
    static const uint16_t OPCAST_MASK = (1u << 6);
    static const uint16_t FWDREF_MASK = (1u << 7);
    static const uint16_t SCOPED_MASK = (1u << 8);

  private:
    le_uint16_t property;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_CV_PROPERTY_HH_ */
