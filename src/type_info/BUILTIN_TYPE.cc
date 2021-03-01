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
#include "type_info/BUILTIN_TYPE.hh"

namespace mspdb {

static const std::string T_NOTYPE("T_NOTYPE");
static const std::string T_ABS("T_ABS");
static const std::string T_SEGMENT("T_SEGMENT");
static const std::string T_VOID("T_VOID");

static const std::string T_HRESULT("T_HRESULT");
static const std::string T_32PHRESULT("T_32PHRESULT");
static const std::string T_64PHRESULT("T_64PHRESULT");

static const std::string T_PVOID("T_PVOID");
static const std::string T_PFVOID("T_PFVOID");
static const std::string T_PHVOID("T_PHVOID");
static const std::string T_32PVOID("T_32PVOID");
static const std::string T_32PFVOID("T_32PFVOID");
static const std::string T_64PVOID("T_64PVOID");

static const std::string T_CURRENCY("T_CURRENCY");
static const std::string T_NBASICSTR("T_NBASICSTR");
static const std::string T_FBASICSTR("T_FBASICSTR");
static const std::string T_NOTTRANS("T_NOTTRANS");
static const std::string T_BIT("T_BIT");
static const std::string T_PASCHAR("T_PASCHAR");

static const std::string T_CHAR("T_CHAR");
static const std::string T_PCHAR("T_PCHAR");
static const std::string T_PFCHAR("T_PFCHAR");
static const std::string T_PHCHAR("T_PHCHAR");
static const std::string T_32PCHAR("T_32PCHAR");
static const std::string T_32PFCHAR("T_32PFCHAR");
static const std::string T_64PCHAR("T_64PCHAR");

static const std::string T_UCHAR("T_UCHAR");
static const std::string T_PUCHAR("T_PUCHAR");
static const std::string T_PFUCHAR("T_PFUCHAR");
static const std::string T_PHUCHAR("T_PHUCHAR");
static const std::string T_32PUCHAR("T_32PUCHAR");
static const std::string T_32PFUCHAR("T_32PFUCHAR");
static const std::string T_64PUCHAR("T_64PUCHAR");

static const std::string T_RCHAR("T_RCHAR");
static const std::string T_PRCHAR("T_PRCHAR");
static const std::string T_PFRCHAR("T_PFRCHAR");
static const std::string T_PHRCHAR("T_PHRCHAR");
static const std::string T_32PRCHAR("T_32PRCHAR");
static const std::string T_32PFRCHAR("T_32PFRCHAR");
static const std::string T_64PRCHAR("T_64PRCHAR");

static const std::string T_WCHAR("T_WCHAR");
static const std::string T_PWCHAR("T_PWCHAR");
static const std::string T_PFWCHAR("T_PFWCHAR");
static const std::string T_PHWCHAR("T_PHWCHAR");
static const std::string T_32PWCHAR("T_32PWCHAR");
static const std::string T_32PFWCHAR("T_32PFWCHAR");
static const std::string T_64PWCHAR("T_64PWCHAR");

static const std::string T_INT1("T_INT1");
static const std::string T_PINT1("T_PINT1");
static const std::string T_PFINT1("T_PFINT1");
static const std::string T_PHINT1("T_PHINT1");
static const std::string T_32PINT1("T_32PINT1");
static const std::string T_32PFINT1("T_32PFINT1");
static const std::string T_64PINT1("T_64PINT1");

static const std::string T_UINT1("T_UINT1");
static const std::string T_PUINT1("T_PUINT1");
static const std::string T_PFUINT1("T_PFUINT1");
static const std::string T_PHUINT1("T_PHUINT1");
static const std::string T_32PUINT1("T_32PUINT1");
static const std::string T_32PFUINT1("T_32PFUINT1");
static const std::string T_64PUINT1("T_64PUINT1");

static const std::string T_SHORT("T_SHORT");
static const std::string T_PSHORT("T_PSHORT");
static const std::string T_PFSHORT("T_PFSHORT");
static const std::string T_PHSHORT("T_PHSHORT");
static const std::string T_32PSHORT("T_32PSHORT");
static const std::string T_32PFSHORT("T_32PFSHORT");
static const std::string T_64PSHORT("T_64PSHORT");

static const std::string T_USHORT("T_USHORT");
static const std::string T_PUSHORT("T_PUSHORT");
static const std::string T_PFUSHORT("T_PFUSHORT");
static const std::string T_PHUSHORT("T_PHUSHORT");
static const std::string T_32PUSHORT("T_32PUSHORT");
static const std::string T_32PFUSHORT("T_32PFUSHORT");
static const std::string T_64PUSHORT("T_64PUSHORT");

static const std::string T_INT2("T_INT2");
static const std::string T_PINT2("T_PINT2");
static const std::string T_PFINT2("T_PFINT2");
static const std::string T_PHINT2("T_PHINT2");
static const std::string T_32PINT2("T_32PINT2");
static const std::string T_32PFINT2("T_32PFINT2");
static const std::string T_64PINT2("T_64PINT2");

static const std::string T_UINT2("T_UINT2");
static const std::string T_PUINT2("T_PUINT2");
static const std::string T_PFUINT2("T_PFUINT2");
static const std::string T_PHUINT2("T_PHUINT2");
static const std::string T_32PUINT2("T_32PUINT2");
static const std::string T_32PFUINT2("T_32PFUINT2");
static const std::string T_64PUINT2("T_64PUINT2");

static const std::string T_LONG("T_LONG");
static const std::string T_PLONG("T_PLONG");
static const std::string T_PFLONG("T_PFLONG");
static const std::string T_PHLONG("T_PHLONG");
static const std::string T_32PLONG("T_32PLONG");
static const std::string T_32PFLONG("T_32PFLONG");
static const std::string T_64PLONG("T_64PLONG");

static const std::string T_ULONG("T_ULONG");
static const std::string T_PULONG("T_PULONG");
static const std::string T_PFULONG("T_PFULONG");
static const std::string T_PHULONG("T_PHULONG");
static const std::string T_32PULONG("T_32PULONG");
static const std::string T_32PFULONG("T_32PFULONG");
static const std::string T_64PULONG("T_64PULONG");

static const std::string T_INT4("T_INT4");
static const std::string T_PINT4("T_PINT4");
static const std::string T_PFINT4("T_PFINT4");
static const std::string T_PHINT4("T_PHINT4");
static const std::string T_32PINT4("T_32PINT4");
static const std::string T_32PFINT4("T_32PFINT4");
static const std::string T_64PINT4("T_64PINT4");

static const std::string T_UINT4("T_UINT4");
static const std::string T_PUINT4("T_PUINT4");
static const std::string T_PFUINT4("T_PFUINT4");
static const std::string T_PHUINT4("T_PHUINT4");
static const std::string T_32PUINT4("T_32PUINT4");
static const std::string T_32PFUINT4("T_32PFUINT4");
static const std::string T_64PUINT4("T_64PUINT4");

static const std::string T_QUAD("T_QUAD");
static const std::string T_PQUAD("T_PQUAD");
static const std::string T_PFQUAD("T_PFQUAD");
static const std::string T_PHQUAD("T_PHQUAD");
static const std::string T_32PQUAD("T_32PQUAD");
static const std::string T_32PFQUAD("T_32PFQUAD");
static const std::string T_64PQUAD("T_64PQUAD");

static const std::string T_UQUAD("T_UQUAD");
static const std::string T_PUQUAD("T_PUQUAD");
static const std::string T_PFUQUAD("T_PFUQUAD");
static const std::string T_PHUQUAD("T_PHUQUAD");
static const std::string T_32PUQUAD("T_32PUQUAD");
static const std::string T_32PFUQUAD("T_32PFUQUAD");
static const std::string T_64PUQUAD("T_64PUQUAD");

static const std::string T_INT8("T_INT8");
static const std::string T_PINT8("T_PINT8");
static const std::string T_PFINT8("T_PFINT8");
static const std::string T_PHINT8("T_PHINT8");
static const std::string T_32PINT8("T_32PINT8");
static const std::string T_32PFINT8("T_32PFINT8");
static const std::string T_64PINT8("T_64PINT8");

static const std::string T_UINT8("T_UINT8");
static const std::string T_PUINT8("T_PUINT8");
static const std::string T_PFUINT8("T_PFUINT8");
static const std::string T_PHUINT8("T_PHUINT8");
static const std::string T_32PUINT8("T_32PUINT8");
static const std::string T_32PFUINT8("T_32PFUINT8");
static const std::string T_64PUINT8("T_64PUINT8");

static const std::string T_OCT("T_OCT");
static const std::string T_POCT("T_POCT");
static const std::string T_PFOCT("T_PFOCT");
static const std::string T_PHOCT("T_PHOCT");
static const std::string T_32POCT("T_32POCT");
static const std::string T_32PFOCT("T_32PFOCT");
static const std::string T_64POCT("T_64POCT");

static const std::string T_UOCT("T_UOCT");
static const std::string T_PUOCT("T_PUOCT");
static const std::string T_PFUOCT("T_PFUOCT");
static const std::string T_PHUOCT("T_PHUOCT");
static const std::string T_32PUOCT("T_32PUOCT");
static const std::string T_32PFUOCT("T_32PFUOCT");
static const std::string T_64PUOCT("T_64PUOCT");

static const std::string T_INT16("T_INT16");
static const std::string T_PINT16("T_PINT16");
static const std::string T_PFINT16("T_PFINT16");
static const std::string T_PHINT16("T_PHINT16");
static const std::string T_32PINT16("T_32PINT16");
static const std::string T_32PFINT16("T_32PFINT16");
static const std::string T_64PINT16("T_64PINT16");

static const std::string T_UINT16("T_UINT16");
static const std::string T_PUINT16("T_PUINT16");
static const std::string T_PFUINT16("T_PFUINT16");
static const std::string T_PHUINT16("T_PHUINT16");
static const std::string T_32PUINT16("T_32PUINT16");
static const std::string T_32PFUINT16("T_32PFUINT16");
static const std::string T_64PUINT16("T_64PUINT16");

static const std::string T_REAL32("T_REAL32");
static const std::string T_PREAL32("T_PREAL32");
static const std::string T_PFREAL32("T_PFREAL32");
static const std::string T_PHREAL32("T_PHREAL32");
static const std::string T_32PREAL32("T_32PREAL32");
static const std::string T_32PFREAL32("T_32PFREAL32");
static const std::string T_64PREAL32("T_64PREAL32");

static const std::string T_REAL48("T_REAL48");
static const std::string T_PREAL48("T_PREAL48");
static const std::string T_PFREAL48("T_PFREAL48");
static const std::string T_PHREAL48("T_PHREAL48");
static const std::string T_32PREAL48("T_32PREAL48");
static const std::string T_32PFREAL48("T_32PFREAL48");
static const std::string T_64PREAL48("T_64PREAL48");

static const std::string T_REAL64("T_REAL64");
static const std::string T_PREAL64("T_PREAL64");
static const std::string T_PFREAL64("T_PFREAL64");
static const std::string T_PHREAL64("T_PHREAL64");
static const std::string T_32PREAL64("T_32PREAL64");
static const std::string T_32PFREAL64("T_32PFREAL64");
static const std::string T_64PREAL64("T_64PREAL64");

static const std::string T_REAL80("T_REAL80");
static const std::string T_PREAL80("T_PREAL80");
static const std::string T_PFREAL80("T_PFREAL80");
static const std::string T_PHREAL80("T_PHREAL80");
static const std::string T_32PREAL80("T_32PREAL80");
static const std::string T_32PFREAL80("T_32PFREAL80");
static const std::string T_64PREAL80("T_64PREAL80");

static const std::string T_REAL128("T_REAL128");
static const std::string T_PREAL128("T_PREAL128");
static const std::string T_PFREAL128("T_PFREAL128");
static const std::string T_PHREAL128("T_PHREAL128");
static const std::string T_32PREAL128("T_32PREAL128");
static const std::string T_32PFREAL128("T_32PFREAL128");
static const std::string T_64PREAL128("T_64PREAL128");

static const std::string T_CPLX32("T_CPLX32");
static const std::string T_PCPLX32("T_PCPLX32");
static const std::string T_PFCPLX32("T_PFCPLX32");
static const std::string T_PHCPLX32("T_PHCPLX32");
static const std::string T_32PCPLX32("T_32PCPLX32");
static const std::string T_32PFCPLX32("T_32PFCPLX32");
static const std::string T_64PCPLX32("T_64PCPLX32");

static const std::string T_CPLX64("T_CPLX64");
static const std::string T_PCPLX64("T_PCPLX64");
static const std::string T_PFCPLX64("T_PFCPLX64");
static const std::string T_PHCPLX64("T_PHCPLX64");
static const std::string T_32PCPLX64("T_32PCPLX64");
static const std::string T_32PFCPLX64("T_32PFCPLX64");
static const std::string T_64PCPLX64("T_64PCPLX64");

static const std::string T_CPLX80("T_CPLX80");
static const std::string T_PCPLX80("T_PCPLX80");
static const std::string T_PFCPLX80("T_PFCPLX80");
static const std::string T_PHCPLX80("T_PHCPLX80");
static const std::string T_32PCPLX80("T_32PCPLX80");
static const std::string T_32PFCPLX80("T_32PFCPLX80");
static const std::string T_64PCPLX80("T_64PCPLX80");

static const std::string T_CPLX128("T_CPLX128");
static const std::string T_PCPLX128("T_PCPLX128");
static const std::string T_PFCPLX128("T_PFCPLX128");
static const std::string T_PHCPLX128("T_PHCPLX128");
static const std::string T_32PCPLX128("T_32PCPLX128");
static const std::string T_32PFCPLX128("T_32PFCPLX128");
static const std::string T_64PCPLX128("T_64PCPLX128");

static const std::string T_BOOL08("T_BOOL08");
static const std::string T_PBOOL08("T_PBOOL08");
static const std::string T_PFBOOL08("T_PFBOOL08");
static const std::string T_PHBOOL08("T_PHBOOL08");
static const std::string T_32PBOOL08("T_32PBOOL08");
static const std::string T_32PFBOOL08("T_32PFBOOL08");
static const std::string T_64PBOOL08("T_64PBOOL08");

static const std::string T_BOOL16("T_BOOL16");
static const std::string T_PBOOL16("T_PBOOL16");
static const std::string T_PFBOOL16("T_PFBOOL16");
static const std::string T_PHBOOL16("T_PHBOOL16");
static const std::string T_32PBOOL16("T_32PBOOL16");
static const std::string T_32PFBOOL16("T_32PFBOOL16");
static const std::string T_64PBOOL16("T_64PBOOL16");

static const std::string T_BOOL32("T_BOOL32");
static const std::string T_PBOOL32("T_PBOOL32");
static const std::string T_PFBOOL32("T_PFBOOL32");
static const std::string T_PHBOOL32("T_PHBOOL32");
static const std::string T_32PBOOL32("T_32PBOOL32");
static const std::string T_32PFBOOL32("T_32PFBOOL32");
static const std::string T_64PBOOL32("T_64PBOOL32");

static const std::string T_BOOL64("T_BOOL64");
static const std::string T_PBOOL64("T_PBOOL64");
static const std::string T_PFBOOL64("T_PFBOOL64");
static const std::string T_PHBOOL64("T_PHBOOL64");
static const std::string T_32PBOOL64("T_32PBOOL64");
static const std::string T_32PFBOOL64("T_32PFBOOL64");
static const std::string T_64PBOOL64("T_64PBOOL64");

static const std::string T_NCVPTR("T_NCVPTR");
static const std::string T_FCVPTR("T_FCVPTR");
static const std::string T_HCVPTR("T_HCVPTR");
static const std::string T_32NCVPTR("T_32NCVPTR");
static const std::string T_32FCVPTR("T_32FCVPTR");
static const std::string T_64NCVPTR("T_64NCVPTR");

static const std::string T_UNKNOWN("T_UNKNOWN");

const std::string& to_string(BUILTIN_TYPE t) {

    switch (t) {
    case BUILTIN_TYPE::T_NOTYPE:
        return T_NOTYPE;
    case BUILTIN_TYPE::T_ABS:
        return T_ABS;
    case BUILTIN_TYPE::T_SEGMENT:
        return T_SEGMENT;
    case BUILTIN_TYPE::T_VOID:
        return T_VOID;

    case BUILTIN_TYPE::T_HRESULT:
        return T_HRESULT;
    case BUILTIN_TYPE::T_32PHRESULT:
        return T_32PHRESULT;
    case BUILTIN_TYPE::T_64PHRESULT:
        return T_64PHRESULT;

    case BUILTIN_TYPE::T_PVOID:
        return T_PVOID;
    case BUILTIN_TYPE::T_PFVOID:
        return T_PFVOID;
    case BUILTIN_TYPE::T_PHVOID:
        return T_PHVOID;
    case BUILTIN_TYPE::T_32PVOID:
        return T_32PVOID;
    case BUILTIN_TYPE::T_32PFVOID:
        return T_32PFVOID;
    case BUILTIN_TYPE::T_64PVOID:
        return T_64PVOID;

    case BUILTIN_TYPE::T_CURRENCY:
        return T_CURRENCY;
    case BUILTIN_TYPE::T_NBASICSTR:
        return T_NBASICSTR;
    case BUILTIN_TYPE::T_FBASICSTR:
        return T_FBASICSTR;
    case BUILTIN_TYPE::T_NOTTRANS:
        return T_NOTTRANS;
    case BUILTIN_TYPE::T_BIT:
        return T_BIT;
    case BUILTIN_TYPE::T_PASCHAR:
        return T_PASCHAR;

    case BUILTIN_TYPE::T_CHAR:
        return T_CHAR;
    case BUILTIN_TYPE::T_PCHAR:
        return T_PCHAR;
    case BUILTIN_TYPE::T_PFCHAR:
        return T_PFCHAR;
    case BUILTIN_TYPE::T_PHCHAR:
        return T_PHCHAR;
    case BUILTIN_TYPE::T_32PCHAR:
        return T_32PCHAR;
    case BUILTIN_TYPE::T_32PFCHAR:
        return T_32PFCHAR;
    case BUILTIN_TYPE::T_64PCHAR:
        return T_64PCHAR;

    case BUILTIN_TYPE::T_UCHAR:
        return T_UCHAR;
    case BUILTIN_TYPE::T_PUCHAR:
        return T_PUCHAR;
    case BUILTIN_TYPE::T_PFUCHAR:
        return T_PFUCHAR;
    case BUILTIN_TYPE::T_PHUCHAR:
        return T_PHUCHAR;
    case BUILTIN_TYPE::T_32PUCHAR:
        return T_32PUCHAR;
    case BUILTIN_TYPE::T_32PFUCHAR:
        return T_32PFUCHAR;
    case BUILTIN_TYPE::T_64PUCHAR:
        return T_64PUCHAR;

    case BUILTIN_TYPE::T_RCHAR:
        return T_RCHAR;
    case BUILTIN_TYPE::T_PRCHAR:
        return T_PRCHAR;
    case BUILTIN_TYPE::T_PFRCHAR:
        return T_PFRCHAR;
    case BUILTIN_TYPE::T_PHRCHAR:
        return T_PHRCHAR;
    case BUILTIN_TYPE::T_32PRCHAR:
        return T_32PRCHAR;
    case BUILTIN_TYPE::T_32PFRCHAR:
        return T_32PFRCHAR;
    case BUILTIN_TYPE::T_64PRCHAR:
        return T_64PRCHAR;

    case BUILTIN_TYPE::T_WCHAR:
        return T_WCHAR;
    case BUILTIN_TYPE::T_PWCHAR:
        return T_PWCHAR;
    case BUILTIN_TYPE::T_PFWCHAR:
        return T_PFWCHAR;
    case BUILTIN_TYPE::T_PHWCHAR:
        return T_PHWCHAR;
    case BUILTIN_TYPE::T_32PWCHAR:
        return T_32PWCHAR;
    case BUILTIN_TYPE::T_32PFWCHAR:
        return T_32PFWCHAR;
    case BUILTIN_TYPE::T_64PWCHAR:
        return T_64PWCHAR;

    case BUILTIN_TYPE::T_INT1:
        return T_INT1;
    case BUILTIN_TYPE::T_PINT1:
        return T_PINT1;
    case BUILTIN_TYPE::T_PFINT1:
        return T_PFINT1;
    case BUILTIN_TYPE::T_PHINT1:
        return T_PHINT1;
    case BUILTIN_TYPE::T_32PINT1:
        return T_32PINT1;
    case BUILTIN_TYPE::T_32PFINT1:
        return T_32PFINT1;
    case BUILTIN_TYPE::T_64PINT1:
        return T_64PINT1;

    case BUILTIN_TYPE::T_UINT1:
        return T_UINT1;
    case BUILTIN_TYPE::T_PUINT1:
        return T_PUINT1;
    case BUILTIN_TYPE::T_PFUINT1:
        return T_PFUINT1;
    case BUILTIN_TYPE::T_PHUINT1:
        return T_PHUINT1;
    case BUILTIN_TYPE::T_32PUINT1:
        return T_32PUINT1;
    case BUILTIN_TYPE::T_32PFUINT1:
        return T_32PFUINT1;
    case BUILTIN_TYPE::T_64PUINT1:
        return T_64PUINT1;

    case BUILTIN_TYPE::T_SHORT:
        return T_SHORT;
    case BUILTIN_TYPE::T_PSHORT:
        return T_PSHORT;
    case BUILTIN_TYPE::T_PFSHORT:
        return T_PFSHORT;
    case BUILTIN_TYPE::T_PHSHORT:
        return T_PHSHORT;
    case BUILTIN_TYPE::T_32PSHORT:
        return T_32PSHORT;
    case BUILTIN_TYPE::T_32PFSHORT:
        return T_32PFSHORT;
    case BUILTIN_TYPE::T_64PSHORT:
        return T_64PSHORT;

    case BUILTIN_TYPE::T_USHORT:
        return T_USHORT;
    case BUILTIN_TYPE::T_PUSHORT:
        return T_PUSHORT;
    case BUILTIN_TYPE::T_PFUSHORT:
        return T_PFUSHORT;
    case BUILTIN_TYPE::T_PHUSHORT:
        return T_PHUSHORT;
    case BUILTIN_TYPE::T_32PUSHORT:
        return T_32PUSHORT;
    case BUILTIN_TYPE::T_32PFUSHORT:
        return T_32PFUSHORT;
    case BUILTIN_TYPE::T_64PUSHORT:
        return T_64PUSHORT;

    case BUILTIN_TYPE::T_INT2:
        return T_INT2;
    case BUILTIN_TYPE::T_PINT2:
        return T_PINT2;
    case BUILTIN_TYPE::T_PFINT2:
        return T_PFINT2;
    case BUILTIN_TYPE::T_PHINT2:
        return T_PHINT2;
    case BUILTIN_TYPE::T_32PINT2:
        return T_32PINT2;
    case BUILTIN_TYPE::T_32PFINT2:
        return T_32PFINT2;
    case BUILTIN_TYPE::T_64PINT2:
        return T_64PINT2;

    case BUILTIN_TYPE::T_UINT2:
        return T_UINT2;
    case BUILTIN_TYPE::T_PUINT2:
        return T_PUINT2;
    case BUILTIN_TYPE::T_PFUINT2:
        return T_PFUINT2;
    case BUILTIN_TYPE::T_PHUINT2:
        return T_PHUINT2;
    case BUILTIN_TYPE::T_32PUINT2:
        return T_32PUINT2;
    case BUILTIN_TYPE::T_32PFUINT2:
        return T_32PFUINT2;
    case BUILTIN_TYPE::T_64PUINT2:
        return T_64PUINT2;

    case BUILTIN_TYPE::T_LONG:
        return T_LONG;
    case BUILTIN_TYPE::T_PLONG:
        return T_PLONG;
    case BUILTIN_TYPE::T_PFLONG:
        return T_PFLONG;
    case BUILTIN_TYPE::T_PHLONG:
        return T_PHLONG;
    case BUILTIN_TYPE::T_32PLONG:
        return T_32PLONG;
    case BUILTIN_TYPE::T_32PFLONG:
        return T_32PFLONG;
    case BUILTIN_TYPE::T_64PLONG:
        return T_64PLONG;

    case BUILTIN_TYPE::T_ULONG:
        return T_ULONG;
    case BUILTIN_TYPE::T_PULONG:
        return T_PULONG;
    case BUILTIN_TYPE::T_PFULONG:
        return T_PFULONG;
    case BUILTIN_TYPE::T_PHULONG:
        return T_PHULONG;
    case BUILTIN_TYPE::T_32PULONG:
        return T_32PULONG;
    case BUILTIN_TYPE::T_32PFULONG:
        return T_32PFULONG;
    case BUILTIN_TYPE::T_64PULONG:
        return T_64PULONG;

    case BUILTIN_TYPE::T_INT4:
        return T_INT4;
    case BUILTIN_TYPE::T_PINT4:
        return T_PINT4;
    case BUILTIN_TYPE::T_PFINT4:
        return T_PFINT4;
    case BUILTIN_TYPE::T_PHINT4:
        return T_PHINT4;
    case BUILTIN_TYPE::T_32PINT4:
        return T_32PINT4;
    case BUILTIN_TYPE::T_32PFINT4:
        return T_32PFINT4;
    case BUILTIN_TYPE::T_64PINT4:
        return T_64PINT4;

    case BUILTIN_TYPE::T_UINT4:
        return T_UINT4;
    case BUILTIN_TYPE::T_PUINT4:
        return T_PUINT4;
    case BUILTIN_TYPE::T_PFUINT4:
        return T_PFUINT4;
    case BUILTIN_TYPE::T_PHUINT4:
        return T_PHUINT4;
    case BUILTIN_TYPE::T_32PUINT4:
        return T_32PUINT4;
    case BUILTIN_TYPE::T_32PFUINT4:
        return T_32PFUINT4;
    case BUILTIN_TYPE::T_64PUINT4:
        return T_64PUINT4;

    case BUILTIN_TYPE::T_QUAD:
        return T_QUAD;
    case BUILTIN_TYPE::T_PQUAD:
        return T_PQUAD;
    case BUILTIN_TYPE::T_PFQUAD:
        return T_PFQUAD;
    case BUILTIN_TYPE::T_PHQUAD:
        return T_PHQUAD;
    case BUILTIN_TYPE::T_32PQUAD:
        return T_32PQUAD;
    case BUILTIN_TYPE::T_32PFQUAD:
        return T_32PFQUAD;
    case BUILTIN_TYPE::T_64PQUAD:
        return T_64PQUAD;

    case BUILTIN_TYPE::T_UQUAD:
        return T_UQUAD;
    case BUILTIN_TYPE::T_PUQUAD:
        return T_PUQUAD;
    case BUILTIN_TYPE::T_PFUQUAD:
        return T_PFUQUAD;
    case BUILTIN_TYPE::T_PHUQUAD:
        return T_PHUQUAD;
    case BUILTIN_TYPE::T_32PUQUAD:
        return T_32PUQUAD;
    case BUILTIN_TYPE::T_32PFUQUAD:
        return T_32PFUQUAD;
    case BUILTIN_TYPE::T_64PUQUAD:
        return T_64PUQUAD;

    case BUILTIN_TYPE::T_INT8:
        return T_INT8;
    case BUILTIN_TYPE::T_PINT8:
        return T_PINT8;
    case BUILTIN_TYPE::T_PFINT8:
        return T_PFINT8;
    case BUILTIN_TYPE::T_PHINT8:
        return T_PHINT8;
    case BUILTIN_TYPE::T_32PINT8:
        return T_32PINT8;
    case BUILTIN_TYPE::T_32PFINT8:
        return T_32PFINT8;
    case BUILTIN_TYPE::T_64PINT8:
        return T_64PINT8;

    case BUILTIN_TYPE::T_UINT8:
        return T_UINT8;
    case BUILTIN_TYPE::T_PUINT8:
        return T_PUINT8;
    case BUILTIN_TYPE::T_PFUINT8:
        return T_PFUINT8;
    case BUILTIN_TYPE::T_PHUINT8:
        return T_PHUINT8;
    case BUILTIN_TYPE::T_32PUINT8:
        return T_32PUINT8;
    case BUILTIN_TYPE::T_32PFUINT8:
        return T_32PFUINT8;
    case BUILTIN_TYPE::T_64PUINT8:
        return T_64PUINT8;

    case BUILTIN_TYPE::T_OCT:
        return T_OCT;
    case BUILTIN_TYPE::T_POCT:
        return T_POCT;
    case BUILTIN_TYPE::T_PFOCT:
        return T_PFOCT;
    case BUILTIN_TYPE::T_PHOCT:
        return T_PHOCT;
    case BUILTIN_TYPE::T_32POCT:
        return T_32POCT;
    case BUILTIN_TYPE::T_32PFOCT:
        return T_32PFOCT;
    case BUILTIN_TYPE::T_64POCT:
        return T_64POCT;

    case BUILTIN_TYPE::T_UOCT:
        return T_UOCT;
    case BUILTIN_TYPE::T_PUOCT:
        return T_PUOCT;
    case BUILTIN_TYPE::T_PFUOCT:
        return T_PFUOCT;
    case BUILTIN_TYPE::T_PHUOCT:
        return T_PHUOCT;
    case BUILTIN_TYPE::T_32PUOCT:
        return T_32PUOCT;
    case BUILTIN_TYPE::T_32PFUOCT:
        return T_32PFUOCT;
    case BUILTIN_TYPE::T_64PUOCT:
        return T_64PUOCT;

    case BUILTIN_TYPE::T_INT16:
        return T_INT16;
    case BUILTIN_TYPE::T_PINT16:
        return T_PINT16;
    case BUILTIN_TYPE::T_PFINT16:
        return T_PFINT16;
    case BUILTIN_TYPE::T_PHINT16:
        return T_PHINT16;
    case BUILTIN_TYPE::T_32PINT16:
        return T_32PINT16;
    case BUILTIN_TYPE::T_32PFINT16:
        return T_32PFINT16;
    case BUILTIN_TYPE::T_64PINT16:
        return T_64PINT16;

    case BUILTIN_TYPE::T_UINT16:
        return T_UINT16;
    case BUILTIN_TYPE::T_PUINT16:
        return T_PUINT16;
    case BUILTIN_TYPE::T_PFUINT16:
        return T_PFUINT16;
    case BUILTIN_TYPE::T_PHUINT16:
        return T_PHUINT16;
    case BUILTIN_TYPE::T_32PUINT16:
        return T_32PUINT16;
    case BUILTIN_TYPE::T_32PFUINT16:
        return T_32PFUINT16;
    case BUILTIN_TYPE::T_64PUINT16:
        return T_64PUINT16;

    case BUILTIN_TYPE::T_REAL32:
        return T_REAL32;
    case BUILTIN_TYPE::T_PREAL32:
        return T_PREAL32;
    case BUILTIN_TYPE::T_PFREAL32:
        return T_PFREAL32;
    case BUILTIN_TYPE::T_PHREAL32:
        return T_PHREAL32;
    case BUILTIN_TYPE::T_32PREAL32:
        return T_32PREAL32;
    case BUILTIN_TYPE::T_32PFREAL32:
        return T_32PFREAL32;
    case BUILTIN_TYPE::T_64PREAL32:
        return T_64PREAL32;

    case BUILTIN_TYPE::T_REAL48:
        return T_REAL48;
    case BUILTIN_TYPE::T_PREAL48:
        return T_PREAL48;
    case BUILTIN_TYPE::T_PFREAL48:
        return T_PFREAL48;
    case BUILTIN_TYPE::T_PHREAL48:
        return T_PHREAL48;
    case BUILTIN_TYPE::T_32PREAL48:
        return T_32PREAL48;
    case BUILTIN_TYPE::T_32PFREAL48:
        return T_32PFREAL48;
    case BUILTIN_TYPE::T_64PREAL48:
        return T_64PREAL48;

    case BUILTIN_TYPE::T_REAL64:
        return T_REAL64;
    case BUILTIN_TYPE::T_PREAL64:
        return T_PREAL64;
    case BUILTIN_TYPE::T_PFREAL64:
        return T_PFREAL64;
    case BUILTIN_TYPE::T_PHREAL64:
        return T_PHREAL64;
    case BUILTIN_TYPE::T_32PREAL64:
        return T_32PREAL64;
    case BUILTIN_TYPE::T_32PFREAL64:
        return T_32PFREAL64;
    case BUILTIN_TYPE::T_64PREAL64:
        return T_64PREAL64;

    case BUILTIN_TYPE::T_REAL80:
        return T_REAL80;
    case BUILTIN_TYPE::T_PREAL80:
        return T_PREAL80;
    case BUILTIN_TYPE::T_PFREAL80:
        return T_PFREAL80;
    case BUILTIN_TYPE::T_PHREAL80:
        return T_PHREAL80;
    case BUILTIN_TYPE::T_32PREAL80:
        return T_32PREAL80;
    case BUILTIN_TYPE::T_32PFREAL80:
        return T_32PFREAL80;
    case BUILTIN_TYPE::T_64PREAL80:
        return T_64PREAL80;

    case BUILTIN_TYPE::T_REAL128:
        return T_REAL128;
    case BUILTIN_TYPE::T_PREAL128:
        return T_PREAL128;
    case BUILTIN_TYPE::T_PFREAL128:
        return T_PFREAL128;
    case BUILTIN_TYPE::T_PHREAL128:
        return T_PHREAL128;
    case BUILTIN_TYPE::T_32PREAL128:
        return T_32PREAL128;
    case BUILTIN_TYPE::T_32PFREAL128:
        return T_32PFREAL128;
    case BUILTIN_TYPE::T_64PREAL128:
        return T_64PREAL128;

    case BUILTIN_TYPE::T_CPLX32:
        return T_CPLX32;
    case BUILTIN_TYPE::T_PCPLX32:
        return T_PCPLX32;
    case BUILTIN_TYPE::T_PFCPLX32:
        return T_PFCPLX32;
    case BUILTIN_TYPE::T_PHCPLX32:
        return T_PHCPLX32;
    case BUILTIN_TYPE::T_32PCPLX32:
        return T_32PCPLX32;
    case BUILTIN_TYPE::T_32PFCPLX32:
        return T_32PFCPLX32;
    case BUILTIN_TYPE::T_64PCPLX32:
        return T_64PCPLX32;

    case BUILTIN_TYPE::T_CPLX64:
        return T_CPLX64;
    case BUILTIN_TYPE::T_PCPLX64:
        return T_PCPLX64;
    case BUILTIN_TYPE::T_PFCPLX64:
        return T_PFCPLX64;
    case BUILTIN_TYPE::T_PHCPLX64:
        return T_PHCPLX64;
    case BUILTIN_TYPE::T_32PCPLX64:
        return T_32PCPLX64;
    case BUILTIN_TYPE::T_32PFCPLX64:
        return T_32PFCPLX64;
    case BUILTIN_TYPE::T_64PCPLX64:
        return T_64PCPLX64;

    case BUILTIN_TYPE::T_CPLX80:
        return T_CPLX80;
    case BUILTIN_TYPE::T_PCPLX80:
        return T_PCPLX80;
    case BUILTIN_TYPE::T_PFCPLX80:
        return T_PFCPLX80;
    case BUILTIN_TYPE::T_PHCPLX80:
        return T_PHCPLX80;
    case BUILTIN_TYPE::T_32PCPLX80:
        return T_32PCPLX80;
    case BUILTIN_TYPE::T_32PFCPLX80:
        return T_32PFCPLX80;
    case BUILTIN_TYPE::T_64PCPLX80:
        return T_64PCPLX80;

    case BUILTIN_TYPE::T_CPLX128:
        return T_CPLX128;
    case BUILTIN_TYPE::T_PCPLX128:
        return T_PCPLX128;
    case BUILTIN_TYPE::T_PFCPLX128:
        return T_PFCPLX128;
    case BUILTIN_TYPE::T_PHCPLX128:
        return T_PHCPLX128;
    case BUILTIN_TYPE::T_32PCPLX128:
        return T_32PCPLX128;
    case BUILTIN_TYPE::T_32PFCPLX128:
        return T_32PFCPLX128;
    case BUILTIN_TYPE::T_64PCPLX128:
        return T_64PCPLX128;

    case BUILTIN_TYPE::T_BOOL08:
        return T_BOOL08;
    case BUILTIN_TYPE::T_PBOOL08:
        return T_PBOOL08;
    case BUILTIN_TYPE::T_PFBOOL08:
        return T_PFBOOL08;
    case BUILTIN_TYPE::T_PHBOOL08:
        return T_PHBOOL08;
    case BUILTIN_TYPE::T_32PBOOL08:
        return T_32PBOOL08;
    case BUILTIN_TYPE::T_32PFBOOL08:
        return T_32PFBOOL08;
    case BUILTIN_TYPE::T_64PBOOL08:
        return T_64PBOOL08;

    case BUILTIN_TYPE::T_BOOL16:
        return T_BOOL16;
    case BUILTIN_TYPE::T_PBOOL16:
        return T_PBOOL16;
    case BUILTIN_TYPE::T_PFBOOL16:
        return T_PFBOOL16;
    case BUILTIN_TYPE::T_PHBOOL16:
        return T_PHBOOL16;
    case BUILTIN_TYPE::T_32PBOOL16:
        return T_32PBOOL16;
    case BUILTIN_TYPE::T_32PFBOOL16:
        return T_32PFBOOL16;
    case BUILTIN_TYPE::T_64PBOOL16:
        return T_64PBOOL16;

    case BUILTIN_TYPE::T_BOOL32:
        return T_BOOL32;
    case BUILTIN_TYPE::T_PBOOL32:
        return T_PBOOL32;
    case BUILTIN_TYPE::T_PFBOOL32:
        return T_PFBOOL32;
    case BUILTIN_TYPE::T_PHBOOL32:
        return T_PHBOOL32;
    case BUILTIN_TYPE::T_32PBOOL32:
        return T_32PBOOL32;
    case BUILTIN_TYPE::T_32PFBOOL32:
        return T_32PFBOOL32;
    case BUILTIN_TYPE::T_64PBOOL32:
        return T_64PBOOL32;

    case BUILTIN_TYPE::T_BOOL64:
        return T_BOOL64;
    case BUILTIN_TYPE::T_PBOOL64:
        return T_PBOOL64;
    case BUILTIN_TYPE::T_PFBOOL64:
        return T_PFBOOL64;
    case BUILTIN_TYPE::T_PHBOOL64:
        return T_PHBOOL64;
    case BUILTIN_TYPE::T_32PBOOL64:
        return T_32PBOOL64;
    case BUILTIN_TYPE::T_32PFBOOL64:
        return T_32PFBOOL64;
    case BUILTIN_TYPE::T_64PBOOL64:
        return T_64PBOOL64;

    case BUILTIN_TYPE::T_NCVPTR:
        return T_NCVPTR;
    case BUILTIN_TYPE::T_FCVPTR:
        return T_FCVPTR;
    case BUILTIN_TYPE::T_HCVPTR:
        return T_HCVPTR;
    case BUILTIN_TYPE::T_32NCVPTR:
        return T_32NCVPTR;
    case BUILTIN_TYPE::T_32FCVPTR:
        return T_32FCVPTR;
    case BUILTIN_TYPE::T_64NCVPTR:
        return T_64NCVPTR;
    }

    return T_UNKNOWN;
}

} /* namespace mspdb */