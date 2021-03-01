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
#ifndef LIBPDB_TYPE_INFO_CV_POINTERTYPE_HH_
#define LIBPDB_TYPE_INFO_CV_POINTERTYPE_HH_

#include <cstdint>
#include <string>

namespace mspdb {

enum class CV_PointerType : uint16_t {
    CV_PTR_NEAR = 0x00000000,
    CV_PTR_FAR = 0x00000001,
    CV_PTR_HUGE = 0x00000002,
    CV_PTR_BASE_SEG = 0x00000003,
    CV_PTR_BASE_VAL = 0x00000004,
    CV_PTR_BASE_SEGVAL = 0x00000005,
    CV_PTR_BASE_ADDR = 0x00000006,
    CV_PTR_BASE_SEGADDR = 0x00000007,
    CV_PTR_BASE_TYPE = 0x00000008,
    CV_PTR_BASE_SELF = 0x00000009,
    CV_PTR_NEAR32 = 0x0000000A,
    CV_PTR_FAR32 = 0x0000000B,
    CV_PTR_64 = 0x0000000C,
    CV_PTR_UNUSEDPTR = 0x0000000D,
};

const std::string& to_string(CV_PointerType);

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_CV_POINTERTYPE_HH_ */