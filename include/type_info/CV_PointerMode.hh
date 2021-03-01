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
#ifndef LIBPDB_TYPE_INFO_CV_POINTERMODE_HH_
#define LIBPDB_TYPE_INFO_CV_POINTERMODE_HH_

#include <cstdint>
#include <string>

namespace mspdb {

enum class CV_PointerMode : uint16_t {
    CV_PTR_MODE_PTR = 0x00000000,
    CV_PTR_MODE_REF = 0x00000001,
    CV_PTR_MODE_PMEM = 0x00000002,
    CV_PTR_MODE_PMFUNC = 0x00000003,
    CV_PTR_MODE_RESERVED = 0x00000004,
};

const std::string& to_string(CV_PointerMode);

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_CV_POINTERMODE_HH_ */