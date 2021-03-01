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
#ifndef LIBPDB_TYPE_INFO_CV_ACCESS_HH_
#define LIBPDB_TYPE_INFO_CV_ACCESS_HH_

#include <cstdint>
#include <string>

namespace mspdb {

enum class CV_Access : uint16_t {
    CV_private = 0x00000001,
    CV_protected = 0x00000002,
    CV_public = 0x00000003,
};

const std::string& to_string(CV_Access);

} /* namespace mspdb */

#endif /* LIBPDB_TYPE_INFO_CV_ACCESS_HH_ */