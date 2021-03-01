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
#ifndef LIBPDB_TYPE_INFO_CV_FieldAttributes_HH_
#define LIBPDB_TYPE_INFO_CV_FieldAttributes_HH_

#include "type_info/CV_Access.hh"
#include "type_info/CV_MethodProperty.hh"

#include "../portable_endian.hh"
#include <cstdint>

namespace mspdb {

class CV_FieldAttributes {
  public:
    inline CV_Access access_type() const {
        static const uint16_t ACCESS_MASK = 0x2;
        static const uint16_t ACCESS_SHIFT = 0x0;
        return static_cast<CV_Access>((attr & ACCESS_MASK) >> ACCESS_SHIFT);
    }
    inline CV_MethodProperty method_property() const {
        static const uint16_t MPROP_MASK = 0x1C;
        static const uint16_t MPROP_SHIFT = 0x2;
        return static_cast<CV_MethodProperty>((attr & MPROP_MASK) >> MPROP_SHIFT);
    }
    inline bool pseudo() const {
        static const uint16_t PSEUDO_MASK = 0x20;
        return attr & PSEUDO_MASK;
    }
    inline bool noinherit() const {
        static const uint16_t NOINHERIT_MASK = 0x40;
        return attr & NOINHERIT_MASK;
    }
    inline bool noconstruct() const {
        static const uint16_t NOCONSTRUCT_MASK = 0x80;
        return attr & NOCONSTRUCT_MASK;
    }
    inline bool compgenx() const {
        static const uint16_t COMPGENX_MASK = 0x100;
        return attr & COMPGENX_MASK;
    }

  private:
    le_uint16_t attr;
};

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_CV_FieldAttributes_HH_ */
