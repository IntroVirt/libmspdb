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
#include "type_info/CV_PointerMode.hh"

namespace mspdb {

static const std::string CV_PTR_MODE_PTR("CV_PTR_MODE_PTR");
static const std::string CV_PTR_MODE_REF("CV_PTR_MODE_REF");
static const std::string CV_PTR_MODE_PMEM("CV_PTR_MODE_PMEM");
static const std::string CV_PTR_MODE_PMFUNC("CV_PTR_MODE_PMFUNC");
static const std::string CV_PTR_MODE_RESERVED("CV_PTR_MODE_RESERVED");

static const std::string CV_PTR_MODE_UNKNOWN("CV_PTR_MODE_UNKNOWN");

const std::string& to_string(CV_PointerMode t) {
    switch (t) {
    case CV_PointerMode::CV_PTR_MODE_PTR:
        return CV_PTR_MODE_PTR;
    case CV_PointerMode::CV_PTR_MODE_REF:
        return CV_PTR_MODE_REF;
    case CV_PointerMode::CV_PTR_MODE_PMEM:
        return CV_PTR_MODE_PMEM;
    case CV_PointerMode::CV_PTR_MODE_PMFUNC:
        return CV_PTR_MODE_PMFUNC;
    case CV_PointerMode::CV_PTR_MODE_RESERVED:
        return CV_PTR_MODE_RESERVED;
    }

    return CV_PTR_MODE_UNKNOWN;
}

} /* namespace mspdb */