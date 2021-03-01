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
#include "type_info/CV_MethodProperty.hh"

namespace mspdb {

static const std::string CV_MTvanilla("CV_MTvanilla");
static const std::string CV_MTvirtual("CV_MTvirtual");
static const std::string CV_MTstatic("CV_MTstatic");
static const std::string CV_MTfriend("CV_MTfriend");
static const std::string CV_MTintro("CV_MTintro");
static const std::string CV_MTpurevirt("CV_MTpurevirt");
static const std::string CV_MTpureintro("CV_MTpureintro");

static const std::string CV_MTunknown("CV_MTunknown");

const std::string& to_string(CV_MethodProperty t) {
    switch (t) {
    case CV_MethodProperty::CV_MTvanilla:
        return CV_MTvanilla;
    case CV_MethodProperty::CV_MTvirtual:
        return CV_MTvirtual;
    case CV_MethodProperty::CV_MTstatic:
        return CV_MTstatic;
    case CV_MethodProperty::CV_MTfriend:
        return CV_MTfriend;
    case CV_MethodProperty::CV_MTintro:
        return CV_MTintro;
    case CV_MethodProperty::CV_MTpurevirt:
        return CV_MTpurevirt;
    case CV_MethodProperty::CV_MTpureintro:
        return CV_MTpureintro;
    }

    return CV_MTunknown;
}

} /* namespace mspdb */