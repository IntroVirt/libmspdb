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
#include "type_info/LF_BUILTIN.hh"
#include "pdb_exception.hh"

namespace mspdb {

class LF_BUILTIN::IMPL {
  public:
    BUILTIN_TYPE builtin_type;
};

bool LF_BUILTIN::pointer() const {
    switch (pImpl->builtin_type) {
    case BUILTIN_TYPE::T_32PINT4:
    case BUILTIN_TYPE::T_32PLONG:
    case BUILTIN_TYPE::T_32PQUAD:
    case BUILTIN_TYPE::T_32PRCHAR:
    case BUILTIN_TYPE::T_32PREAL32:
    case BUILTIN_TYPE::T_32PREAL64:
    case BUILTIN_TYPE::T_32PSHORT:
    case BUILTIN_TYPE::T_32PUCHAR:
    case BUILTIN_TYPE::T_32PUINT4:
    case BUILTIN_TYPE::T_32PULONG:
    case BUILTIN_TYPE::T_32PUQUAD:
    case BUILTIN_TYPE::T_32PUSHORT:
    case BUILTIN_TYPE::T_32PVOID:
    case BUILTIN_TYPE::T_32PWCHAR:
    case BUILTIN_TYPE::T_64PLONG:
    case BUILTIN_TYPE::T_64PQUAD:
    case BUILTIN_TYPE::T_64PRCHAR:
    case BUILTIN_TYPE::T_64PUCHAR:
    case BUILTIN_TYPE::T_64PWCHAR:
    case BUILTIN_TYPE::T_64PULONG:
    case BUILTIN_TYPE::T_64PUQUAD:
    case BUILTIN_TYPE::T_64PUSHORT:
    case BUILTIN_TYPE::T_64PVOID:
        return true;
    default:
        return false;
    }
}

BUILTIN_TYPE LF_BUILTIN::builtin_type() const { return pImpl->builtin_type; }

LF_BUILTIN::LF_BUILTIN(BUILTIN_TYPE type)
    : LF_TYPE(LEAF_TYPE::LF_BUILTIN), pImpl(std::make_unique<IMPL>()) {

    pImpl->builtin_type = type;
}

int64_t LF_BUILTIN::size() const {

    switch (pImpl->builtin_type) {
    case BUILTIN_TYPE::T_RCHAR:
    case BUILTIN_TYPE::T_CHAR:
    case BUILTIN_TYPE::T_UCHAR:
        return 1;
    case BUILTIN_TYPE::T_SHORT:
    case BUILTIN_TYPE::T_USHORT:
    case BUILTIN_TYPE::T_WCHAR:
        return 2;
    case BUILTIN_TYPE::T_LONG:
    case BUILTIN_TYPE::T_ULONG:
    case BUILTIN_TYPE::T_INT4:
    case BUILTIN_TYPE::T_UINT4:
    case BUILTIN_TYPE::T_REAL32:
        return 4;
    case BUILTIN_TYPE::T_QUAD:
    case BUILTIN_TYPE::T_UQUAD:
    case BUILTIN_TYPE::T_INT8:
    case BUILTIN_TYPE::T_REAL64:
        return 8;
    case BUILTIN_TYPE::T_REAL80:
        return 10;
    default:
        return 0;
    }

    return 0;
}

LF_BUILTIN::~LF_BUILTIN() = default;

} /* namespace mspdb */
