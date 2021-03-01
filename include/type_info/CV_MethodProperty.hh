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
#ifndef LIBPDB_TYPE_INFO_CV_METHODPROPERTY_HH_
#define LIBPDB_TYPE_INFO_CV_METHODPROPERTY_HH_

#include <cstdint>
#include <string>

namespace mspdb {

enum class CV_MethodProperty : uint16_t {
    CV_MTvanilla = 0x00000000,
    CV_MTvirtual = 0x00000001,
    CV_MTstatic = 0x00000002,
    CV_MTfriend = 0x00000003,
    CV_MTintro = 0x00000004,
    CV_MTpurevirt = 0x00000005,
    CV_MTpureintro = 0x00000006,
};

const std::string& to_string(CV_MethodProperty);

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_CV_METHODPROPERTY_HH_ */