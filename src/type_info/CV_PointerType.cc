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
#include "type_info/CV_PointerType.hh"

namespace mspdb {

static const std::string CV_PTR_NEAR("CV_PTR_NEAR");
static const std::string CV_PTR_FAR("CV_PTR_FAR");
static const std::string CV_PTR_HUGE("CV_PTR_HUGE");
static const std::string CV_PTR_BASE_SEG("CV_PTR_BASE_SEG");
static const std::string CV_PTR_BASE_VAL("CV_PTR_BASE_VAL");
static const std::string CV_PTR_BASE_SEGVAL("CV_PTR_BASE_SEGVAL");
static const std::string CV_PTR_BASE_ADDR("CV_PTR_BASE_ADDR");
static const std::string CV_PTR_BASE_SEGADDR("CV_PTR_BASE_SEGADDR");
static const std::string CV_PTR_BASE_TYPE("CV_PTR_BASE_TYPE");
static const std::string CV_PTR_BASE_SELF("CV_PTR_BASE_SELF");
static const std::string CV_PTR_NEAR32("CV_PTR_NEAR32");
static const std::string CV_PTR_FAR32("CV_PTR_FAR32");
static const std::string CV_PTR_64("CV_PTR_64");
static const std::string CV_PTR_UNUSEDPTR("CV_PTR_UNUSEDPTR");

static const std::string CV_PTR_UNKNOWN("CV_PTR_UNKNOWN");

const std::string& to_string(CV_PointerType t) {
    switch (t) {
    case CV_PointerType::CV_PTR_NEAR:
        return CV_PTR_NEAR;
    case CV_PointerType::CV_PTR_FAR:
        return CV_PTR_FAR;
    case CV_PointerType::CV_PTR_HUGE:
        return CV_PTR_HUGE;
    case CV_PointerType::CV_PTR_BASE_SEG:
        return CV_PTR_BASE_SEG;
    case CV_PointerType::CV_PTR_BASE_VAL:
        return CV_PTR_BASE_VAL;
    case CV_PointerType::CV_PTR_BASE_SEGVAL:
        return CV_PTR_BASE_SEGVAL;
    case CV_PointerType::CV_PTR_BASE_ADDR:
        return CV_PTR_BASE_ADDR;
    case CV_PointerType::CV_PTR_BASE_SEGADDR:
        return CV_PTR_BASE_SEGADDR;
    case CV_PointerType::CV_PTR_BASE_TYPE:
        return CV_PTR_BASE_TYPE;
    case CV_PointerType::CV_PTR_BASE_SELF:
        return CV_PTR_BASE_SELF;
    case CV_PointerType::CV_PTR_NEAR32:
        return CV_PTR_NEAR32;
    case CV_PointerType::CV_PTR_FAR32:
        return CV_PTR_FAR32;
    case CV_PointerType::CV_PTR_64:
        return CV_PTR_64;
    case CV_PointerType::CV_PTR_UNUSEDPTR:
        return CV_PTR_UNUSEDPTR;
    }

    return CV_PTR_UNKNOWN;
}

} /* namespace mspdb */