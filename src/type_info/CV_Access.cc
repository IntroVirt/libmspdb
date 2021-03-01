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
#include "type_info/CV_Access.hh"

namespace mspdb {

static const std::string CV_private("CV_private");
static const std::string CV_protected("CV_protected");
static const std::string CV_public("CV_public");

static const std::string CV_unknown("CV_unknown");

const std::string& to_string(CV_Access t) {

    switch (t) {
    case CV_Access::CV_private:
        return CV_private;
    case CV_Access::CV_protected:
        return CV_protected;
    case CV_Access::CV_public:
        return CV_public;
    }

    return CV_unknown;
}

} /* namespace mspdb */