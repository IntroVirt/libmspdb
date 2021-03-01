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
#include "type_info/LEAF_TYPE.hh"

namespace mspdb {

static const std::string LF_MODIFIER_16t("LF_MODIFIER_16t");
static const std::string LF_POINTER_16t("LF_POINTER_16t");
static const std::string LF_ARRAY_16t("LF_ARRAY_16t");
static const std::string LF_CLASS_16t("LF_CLASS_16t");
static const std::string LF_STRUCTURE_16t("LF_STRUCTURE_16t");
static const std::string LF_UNION_16t("LF_UNION_16t");
static const std::string LF_ENUM_16t("LF_ENUM_16t");
static const std::string LF_PROCEDURE_16t("LF_PROCEDURE_16t");
static const std::string LF_MFUNCTION_16t("LF_MFUNCTION_16t");
static const std::string LF_VTSHAPE("LF_VTSHAPE");
static const std::string LF_COBOL0_16t("LF_COBOL0_16t");
static const std::string LF_COBOL1("LF_COBOL1");
static const std::string LF_BARRAY_16t("LF_BARRAY_16t");
static const std::string LF_LABEL("LF_LABEL");
static const std::string LF_NULL("LF_NULL");
static const std::string LF_NOTTRAN("LF_NOTTRAN");
static const std::string LF_DIMARRAY_16t("LF_DIMARRAY_16t");
static const std::string LF_VFTPATH_16t("LF_VFTPATH_16t");
static const std::string LF_PRECOMP_16t("LF_PRECOMP_16t");
static const std::string LF_ENDPRECOMP("LF_ENDPRECOMP");
static const std::string LF_OEM_16t("LF_OEM_16t");
static const std::string LF_TYPESERVER_ST("LF_TYPESERVER_ST");
static const std::string LF_SKIP_16t("LF_SKIP_16t");
static const std::string LF_ARGLIST_16t("LF_ARGLIST_16t");
static const std::string LF_DEFARG_16t("LF_DEFARG_16t");
static const std::string LF_LIST("LF_LIST");
static const std::string LF_FIELDLIST_16t("LF_FIELDLIST_16t");
static const std::string LF_DERIVED_16t("LF_DERIVED_16t");
static const std::string LF_BITFIELD_16t("LF_BITFIELD_16t");
static const std::string LF_METHODLIST_16t("LF_METHODLIST_16t");
static const std::string LF_DIMCONU_16t("LF_DIMCONU_16t");
static const std::string LF_DIMCONLU_16t("LF_DIMCONLU_16t");
static const std::string LF_DIMVARU_16t("LF_DIMVARU_16t");
static const std::string LF_DIMVARLU_16t("LF_DIMVARLU_16t");
static const std::string LF_REFSYM("LF_REFSYM");
static const std::string LF_BCLASS_16t("LF_BCLASS_16t");
static const std::string LF_VBCLASS_16t("LF_VBCLASS_16t");
static const std::string LF_IVBCLASS_16t("LF_IVBCLASS_16t");
static const std::string LF_ENUMERATE_ST("LF_ENUMERATE_ST");
static const std::string LF_FRIENDFCN_16t("LF_FRIENDFCN_16t");
static const std::string LF_INDEX_16t("LF_INDEX_16t");
static const std::string LF_MEMBER_16t("LF_MEMBER_16t");
static const std::string LF_STMEMBER_16t("LF_STMEMBER_16t");
static const std::string LF_METHOD_16t("LF_METHOD_16t");
static const std::string LF_NESTTYPE_16t("LF_NESTTYPE_16t");
static const std::string LF_VFUNCTAB_16t("LF_VFUNCTAB_16t");
static const std::string LF_FRIENDCLS_16t("LF_FRIENDCLS_16t");
static const std::string LF_ONEMETHOD_16t("LF_ONEMETHOD_16t");
static const std::string LF_VFUNCOFF_16t("LF_VFUNCOFF_16t");
static const std::string LF_TI16_MAX("LF_TI16_MAX");
static const std::string LF_MODIFIER("LF_MODIFIER");
static const std::string LF_POINTER("LF_POINTER");
static const std::string LF_ARRAY_ST("LF_ARRAY_ST");
static const std::string LF_CLASS_ST("LF_CLASS_ST");
static const std::string LF_STRUCTURE_ST("LF_STRUCTURE_ST");
static const std::string LF_UNION_ST("LF_UNION_ST");
static const std::string LF_ENUM_ST("LF_ENUM_ST");
static const std::string LF_PROCEDURE("LF_PROCEDURE");
static const std::string LF_MFUNCTION("LF_MFUNCTION");
static const std::string LF_COBOL0("LF_COBOL0");
static const std::string LF_BARRAY("LF_BARRAY");
static const std::string LF_DIMARRAY_ST("LF_DIMARRAY_ST");
static const std::string LF_VFTPATH("LF_VFTPATH");
static const std::string LF_PRECOMP_ST("LF_PRECOMP_ST");
static const std::string LF_OEM("LF_OEM");
static const std::string LF_ALIAS_ST("LF_ALIAS_ST");
static const std::string LF_OEM2("LF_OEM2");
static const std::string LF_SKIP("LF_SKIP");
static const std::string LF_ARGLIST("LF_ARGLIST");
static const std::string LF_DEFARG_ST("LF_DEFARG_ST");
static const std::string LF_FIELDLIST("LF_FIELDLIST");
static const std::string LF_DERIVED("LF_DERIVED");
static const std::string LF_BITFIELD("LF_BITFIELD");
static const std::string LF_METHODLIST("LF_METHODLIST");
static const std::string LF_DIMCONU("LF_DIMCONU");
static const std::string LF_DIMCONLU("LF_DIMCONLU");
static const std::string LF_DIMVARU("LF_DIMVARU");
static const std::string LF_DIMVARLU("LF_DIMVARLU");
static const std::string LF_BCLASS("LF_BCLASS");
static const std::string LF_VBCLASS("LF_VBCLASS");
static const std::string LF_IVBCLASS("LF_IVBCLASS");
static const std::string LF_FRIENDFCN_ST("LF_FRIENDFCN_ST");
static const std::string LF_INDEX("LF_INDEX");
static const std::string LF_MEMBER_ST("LF_MEMBER_ST");
static const std::string LF_STMEMBER_ST("LF_STMEMBER_ST");
static const std::string LF_METHOD_ST("LF_METHOD_ST");
static const std::string LF_NESTTYPE_ST("LF_NESTTYPE_ST");
static const std::string LF_VFUNCTAB("LF_VFUNCTAB");
static const std::string LF_FRIENDCLS("LF_FRIENDCLS");
static const std::string LF_ONEMETHOD_ST("LF_ONEMETHOD_ST");
static const std::string LF_VFUNCOFF("LF_VFUNCOFF");
static const std::string LF_NESTTYPEEX_ST("LF_NESTTYPEEX_ST");
static const std::string LF_MEMBERMODIFY_ST("LF_MEMBERMODIFY_ST");
static const std::string LF_MANAGED_ST("LF_MANAGED_ST");
static const std::string LF_ST_MAX("LF_ST_MAX");
static const std::string LF_TYPESERVER("LF_TYPESERVER");
static const std::string LF_ENUMERATE("LF_ENUMERATE");
static const std::string LF_ARRAY("LF_ARRAY");
static const std::string LF_CLASS("LF_CLASS");
static const std::string LF_STRUCTURE("LF_STRUCTURE");
static const std::string LF_UNION("LF_UNION");
static const std::string LF_ENUM("LF_ENUM");
static const std::string LF_DIMARRAY("LF_DIMARRAY");
static const std::string LF_PRECOMP("LF_PRECOMP");
static const std::string LF_ALIAS("LF_ALIAS");
static const std::string LF_DEFARG("LF_DEFARG");
static const std::string LF_FRIENDFCN("LF_FRIENDFCN");
static const std::string LF_MEMBER("LF_MEMBER");
static const std::string LF_STMEMBER("LF_STMEMBER");
static const std::string LF_METHOD("LF_METHOD");
static const std::string LF_NESTTYPE("LF_NESTTYPE");
static const std::string LF_ONEMETHOD("LF_ONEMETHOD");
static const std::string LF_NESTTYPEEX("LF_NESTTYPEEX");
static const std::string LF_MEMBERMODIFY("LF_MEMBERMODIFY");
static const std::string LF_MANAGED("LF_MANAGED");
static const std::string LF_TYPESERVER2("LF_TYPESERVER2");
// static const std::string LF_NUMERIC("LF_NUMERIC");
static const std::string LF_CHAR("LF_CHAR");
static const std::string LF_SHORT("LF_SHORT");
static const std::string LF_USHORT("LF_USHORT");
static const std::string LF_LONG("LF_LONG");
static const std::string LF_ULONG("LF_ULONG");
static const std::string LF_REAL32("LF_REAL32");
static const std::string LF_REAL64("LF_REAL64");
static const std::string LF_REAL80("LF_REAL80");
static const std::string LF_REAL128("LF_REAL128");
static const std::string LF_QUADWORD("LF_QUADWORD");
static const std::string LF_UQUADWORD("LF_UQUADWORD");
static const std::string LF_REAL48("LF_REAL48");
static const std::string LF_COMPLEX32("LF_COMPLEX32");
static const std::string LF_COMPLEX64("LF_COMPLEX64");
static const std::string LF_COMPLEX80("LF_COMPLEX80");
static const std::string LF_COMPLEX128("LF_COMPLEX128");
static const std::string LF_VARSTRING("LF_VARSTRING");
static const std::string LF_OCTWORD("LF_OCTWORD");
static const std::string LF_UOCTWORD("LF_UOCTWORD");
static const std::string LF_DECIMAL("LF_DECIMAL");
static const std::string LF_DATE("LF_DATE");
static const std::string LF_UTF8STRING("LF_UTF8STRING");
static const std::string LF_PAD0("LF_PAD0");
static const std::string LF_PAD1("LF_PAD1");
static const std::string LF_PAD2("LF_PAD2");
static const std::string LF_PAD3("LF_PAD3");
static const std::string LF_PAD4("LF_PAD4");
static const std::string LF_PAD5("LF_PAD5");
static const std::string LF_PAD6("LF_PAD6");
static const std::string LF_PAD7("LF_PAD7");
static const std::string LF_PAD8("LF_PAD8");
static const std::string LF_PAD9("LF_PAD9");
static const std::string LF_PAD10("LF_PAD10");
static const std::string LF_PAD11("LF_PAD11");
static const std::string LF_PAD12("LF_PAD12");
static const std::string LF_PAD13("LF_PAD13");
static const std::string LF_PAD14("LF_PAD14");
static const std::string LF_PAD15("LF_PAD15");

static const std::string LF_BUILTIN("LF_BUILTIN");
static const std::string LF_UNKNOWN("LF_UNKNOWN");

const std::string& to_string(LEAF_TYPE type) {
    switch (type) {
    case LEAF_TYPE::LF_MODIFIER_16t:
        return LF_MODIFIER_16t;
    case LEAF_TYPE::LF_POINTER_16t:
        return LF_POINTER_16t;
    case LEAF_TYPE::LF_ARRAY_16t:
        return LF_ARRAY_16t;
    case LEAF_TYPE::LF_CLASS_16t:
        return LF_CLASS_16t;
    case LEAF_TYPE::LF_STRUCTURE_16t:
        return LF_STRUCTURE_16t;
    case LEAF_TYPE::LF_UNION_16t:
        return LF_UNION_16t;
    case LEAF_TYPE::LF_ENUM_16t:
        return LF_ENUM_16t;
    case LEAF_TYPE::LF_PROCEDURE_16t:
        return LF_PROCEDURE_16t;
    case LEAF_TYPE::LF_MFUNCTION_16t:
        return LF_MFUNCTION_16t;
    case LEAF_TYPE::LF_VTSHAPE:
        return LF_VTSHAPE;
    case LEAF_TYPE::LF_COBOL0_16t:
        return LF_COBOL0_16t;
    case LEAF_TYPE::LF_COBOL1:
        return LF_COBOL1;
    case LEAF_TYPE::LF_BARRAY_16t:
        return LF_BARRAY_16t;
    case LEAF_TYPE::LF_LABEL:
        return LF_LABEL;
    case LEAF_TYPE::LF_NULL:
        return LF_NULL;
    case LEAF_TYPE::LF_NOTTRAN:
        return LF_NOTTRAN;
    case LEAF_TYPE::LF_DIMARRAY_16t:
        return LF_DIMARRAY_16t;
    case LEAF_TYPE::LF_VFTPATH_16t:
        return LF_VFTPATH_16t;
    case LEAF_TYPE::LF_PRECOMP_16t:
        return LF_PRECOMP_16t;
    case LEAF_TYPE::LF_ENDPRECOMP:
        return LF_ENDPRECOMP;
    case LEAF_TYPE::LF_OEM_16t:
        return LF_OEM_16t;
    case LEAF_TYPE::LF_TYPESERVER_ST:
        return LF_TYPESERVER_ST;
    case LEAF_TYPE::LF_SKIP_16t:
        return LF_SKIP_16t;
    case LEAF_TYPE::LF_ARGLIST_16t:
        return LF_ARGLIST_16t;
    case LEAF_TYPE::LF_DEFARG_16t:
        return LF_DEFARG_16t;
    case LEAF_TYPE::LF_LIST:
        return LF_LIST;
    case LEAF_TYPE::LF_FIELDLIST_16t:
        return LF_FIELDLIST_16t;
    case LEAF_TYPE::LF_DERIVED_16t:
        return LF_DERIVED_16t;
    case LEAF_TYPE::LF_BITFIELD_16t:
        return LF_BITFIELD_16t;
    case LEAF_TYPE::LF_METHODLIST_16t:
        return LF_METHODLIST_16t;
    case LEAF_TYPE::LF_DIMCONU_16t:
        return LF_DIMCONU_16t;
    case LEAF_TYPE::LF_DIMCONLU_16t:
        return LF_DIMCONLU_16t;
    case LEAF_TYPE::LF_DIMVARU_16t:
        return LF_DIMVARU_16t;
    case LEAF_TYPE::LF_DIMVARLU_16t:
        return LF_DIMVARLU_16t;
    case LEAF_TYPE::LF_REFSYM:
        return LF_REFSYM;
    case LEAF_TYPE::LF_BCLASS_16t:
        return LF_BCLASS_16t;
    case LEAF_TYPE::LF_VBCLASS_16t:
        return LF_VBCLASS_16t;
    case LEAF_TYPE::LF_IVBCLASS_16t:
        return LF_IVBCLASS_16t;
    case LEAF_TYPE::LF_ENUMERATE_ST:
        return LF_ENUMERATE_ST;
    case LEAF_TYPE::LF_FRIENDFCN_16t:
        return LF_FRIENDFCN_16t;
    case LEAF_TYPE::LF_INDEX_16t:
        return LF_INDEX_16t;
    case LEAF_TYPE::LF_MEMBER_16t:
        return LF_MEMBER_16t;
    case LEAF_TYPE::LF_STMEMBER_16t:
        return LF_STMEMBER_16t;
    case LEAF_TYPE::LF_METHOD_16t:
        return LF_METHOD_16t;
    case LEAF_TYPE::LF_NESTTYPE_16t:
        return LF_NESTTYPE_16t;
    case LEAF_TYPE::LF_VFUNCTAB_16t:
        return LF_VFUNCTAB_16t;
    case LEAF_TYPE::LF_FRIENDCLS_16t:
        return LF_FRIENDCLS_16t;
    case LEAF_TYPE::LF_ONEMETHOD_16t:
        return LF_ONEMETHOD_16t;
    case LEAF_TYPE::LF_VFUNCOFF_16t:
        return LF_VFUNCOFF_16t;
    case LEAF_TYPE::LF_TI16_MAX:
        return LF_TI16_MAX;
    case LEAF_TYPE::LF_MODIFIER:
        return LF_MODIFIER;
    case LEAF_TYPE::LF_POINTER:
        return LF_POINTER;
    case LEAF_TYPE::LF_ARRAY_ST:
        return LF_ARRAY_ST;
    case LEAF_TYPE::LF_CLASS_ST:
        return LF_CLASS_ST;
    case LEAF_TYPE::LF_STRUCTURE_ST:
        return LF_STRUCTURE_ST;
    case LEAF_TYPE::LF_UNION_ST:
        return LF_UNION_ST;
    case LEAF_TYPE::LF_ENUM_ST:
        return LF_ENUM_ST;
    case LEAF_TYPE::LF_PROCEDURE:
        return LF_PROCEDURE;
    case LEAF_TYPE::LF_MFUNCTION:
        return LF_MFUNCTION;
    case LEAF_TYPE::LF_COBOL0:
        return LF_COBOL0;
    case LEAF_TYPE::LF_BARRAY:
        return LF_BARRAY;
    case LEAF_TYPE::LF_DIMARRAY_ST:
        return LF_DIMARRAY_ST;
    case LEAF_TYPE::LF_VFTPATH:
        return LF_VFTPATH;
    case LEAF_TYPE::LF_PRECOMP_ST:
        return LF_PRECOMP_ST;
    case LEAF_TYPE::LF_OEM:
        return LF_OEM;
    case LEAF_TYPE::LF_ALIAS_ST:
        return LF_ALIAS_ST;
    case LEAF_TYPE::LF_OEM2:
        return LF_OEM2;
    case LEAF_TYPE::LF_SKIP:
        return LF_SKIP;
    case LEAF_TYPE::LF_ARGLIST:
        return LF_ARGLIST;
    case LEAF_TYPE::LF_DEFARG_ST:
        return LF_DEFARG_ST;
    case LEAF_TYPE::LF_FIELDLIST:
        return LF_FIELDLIST;
    case LEAF_TYPE::LF_DERIVED:
        return LF_DERIVED;
    case LEAF_TYPE::LF_BITFIELD:
        return LF_BITFIELD;
    case LEAF_TYPE::LF_METHODLIST:
        return LF_METHODLIST;
    case LEAF_TYPE::LF_DIMCONU:
        return LF_DIMCONU;
    case LEAF_TYPE::LF_DIMCONLU:
        return LF_DIMCONLU;
    case LEAF_TYPE::LF_DIMVARU:
        return LF_DIMVARU;
    case LEAF_TYPE::LF_DIMVARLU:
        return LF_DIMVARLU;
    case LEAF_TYPE::LF_BCLASS:
        return LF_BCLASS;
    case LEAF_TYPE::LF_VBCLASS:
        return LF_VBCLASS;
    case LEAF_TYPE::LF_IVBCLASS:
        return LF_IVBCLASS;
    case LEAF_TYPE::LF_FRIENDFCN_ST:
        return LF_FRIENDFCN_ST;
    case LEAF_TYPE::LF_INDEX:
        return LF_INDEX;
    case LEAF_TYPE::LF_MEMBER_ST:
        return LF_MEMBER_ST;
    case LEAF_TYPE::LF_STMEMBER_ST:
        return LF_STMEMBER_ST;
    case LEAF_TYPE::LF_METHOD_ST:
        return LF_METHOD_ST;
    case LEAF_TYPE::LF_NESTTYPE_ST:
        return LF_NESTTYPE_ST;
    case LEAF_TYPE::LF_VFUNCTAB:
        return LF_VFUNCTAB;
    case LEAF_TYPE::LF_FRIENDCLS:
        return LF_FRIENDCLS;
    case LEAF_TYPE::LF_ONEMETHOD_ST:
        return LF_ONEMETHOD_ST;
    case LEAF_TYPE::LF_VFUNCOFF:
        return LF_VFUNCOFF;
    case LEAF_TYPE::LF_NESTTYPEEX_ST:
        return LF_NESTTYPEEX_ST;
    case LEAF_TYPE::LF_MEMBERMODIFY_ST:
        return LF_MEMBERMODIFY_ST;
    case LEAF_TYPE::LF_MANAGED_ST:
        return LF_MANAGED_ST;
    case LEAF_TYPE::LF_ST_MAX:
        return LF_ST_MAX;
    case LEAF_TYPE::LF_TYPESERVER:
        return LF_TYPESERVER;
    case LEAF_TYPE::LF_ENUMERATE:
        return LF_ENUMERATE;
    case LEAF_TYPE::LF_ARRAY:
        return LF_ARRAY;
    case LEAF_TYPE::LF_CLASS:
        return LF_CLASS;
    case LEAF_TYPE::LF_STRUCTURE:
        return LF_STRUCTURE;
    case LEAF_TYPE::LF_UNION:
        return LF_UNION;
    case LEAF_TYPE::LF_ENUM:
        return LF_ENUM;
    case LEAF_TYPE::LF_DIMARRAY:
        return LF_DIMARRAY;
    case LEAF_TYPE::LF_PRECOMP:
        return LF_PRECOMP;
    case LEAF_TYPE::LF_ALIAS:
        return LF_ALIAS;
    case LEAF_TYPE::LF_DEFARG:
        return LF_DEFARG;
    case LEAF_TYPE::LF_FRIENDFCN:
        return LF_FRIENDFCN;
    case LEAF_TYPE::LF_MEMBER:
        return LF_MEMBER;
    case LEAF_TYPE::LF_STMEMBER:
        return LF_STMEMBER;
    case LEAF_TYPE::LF_METHOD:
        return LF_METHOD;
    case LEAF_TYPE::LF_NESTTYPE:
        return LF_NESTTYPE;
    case LEAF_TYPE::LF_ONEMETHOD:
        return LF_ONEMETHOD;
    case LEAF_TYPE::LF_NESTTYPEEX:
        return LF_NESTTYPEEX;
    case LEAF_TYPE::LF_MEMBERMODIFY:
        return LF_MEMBERMODIFY;
    case LEAF_TYPE::LF_MANAGED:
        return LF_MANAGED;
    case LEAF_TYPE::LF_TYPESERVER2:
        return LF_TYPESERVER2;
    // case LEAF_TYPE::LF_NUMERIC: return LF_NUMERIC;
    case LEAF_TYPE::LF_CHAR:
        return LF_CHAR;
    case LEAF_TYPE::LF_SHORT:
        return LF_SHORT;
    case LEAF_TYPE::LF_USHORT:
        return LF_USHORT;
    case LEAF_TYPE::LF_LONG:
        return LF_LONG;
    case LEAF_TYPE::LF_ULONG:
        return LF_ULONG;
    case LEAF_TYPE::LF_REAL32:
        return LF_REAL32;
    case LEAF_TYPE::LF_REAL64:
        return LF_REAL64;
    case LEAF_TYPE::LF_REAL80:
        return LF_REAL80;
    case LEAF_TYPE::LF_REAL128:
        return LF_REAL128;
    case LEAF_TYPE::LF_QUADWORD:
        return LF_QUADWORD;
    case LEAF_TYPE::LF_UQUADWORD:
        return LF_UQUADWORD;
    case LEAF_TYPE::LF_REAL48:
        return LF_REAL48;
    case LEAF_TYPE::LF_COMPLEX32:
        return LF_COMPLEX32;
    case LEAF_TYPE::LF_COMPLEX64:
        return LF_COMPLEX64;
    case LEAF_TYPE::LF_COMPLEX80:
        return LF_COMPLEX80;
    case LEAF_TYPE::LF_COMPLEX128:
        return LF_COMPLEX128;
    case LEAF_TYPE::LF_VARSTRING:
        return LF_VARSTRING;
    case LEAF_TYPE::LF_OCTWORD:
        return LF_OCTWORD;
    case LEAF_TYPE::LF_UOCTWORD:
        return LF_UOCTWORD;
    case LEAF_TYPE::LF_DECIMAL:
        return LF_DECIMAL;
    case LEAF_TYPE::LF_DATE:
        return LF_DATE;
    case LEAF_TYPE::LF_UTF8STRING:
        return LF_UTF8STRING;
    case LEAF_TYPE::LF_PAD0:
        return LF_PAD0;
    case LEAF_TYPE::LF_PAD1:
        return LF_PAD1;
    case LEAF_TYPE::LF_PAD2:
        return LF_PAD2;
    case LEAF_TYPE::LF_PAD3:
        return LF_PAD3;
    case LEAF_TYPE::LF_PAD4:
        return LF_PAD4;
    case LEAF_TYPE::LF_PAD5:
        return LF_PAD5;
    case LEAF_TYPE::LF_PAD6:
        return LF_PAD6;
    case LEAF_TYPE::LF_PAD7:
        return LF_PAD7;
    case LEAF_TYPE::LF_PAD8:
        return LF_PAD8;
    case LEAF_TYPE::LF_PAD9:
        return LF_PAD9;
    case LEAF_TYPE::LF_PAD10:
        return LF_PAD10;
    case LEAF_TYPE::LF_PAD11:
        return LF_PAD11;
    case LEAF_TYPE::LF_PAD12:
        return LF_PAD12;
    case LEAF_TYPE::LF_PAD13:
        return LF_PAD13;
    case LEAF_TYPE::LF_PAD14:
        return LF_PAD14;
    case LEAF_TYPE::LF_PAD15:
        return LF_PAD15;
    case LEAF_TYPE::LF_BUILTIN:
        return LF_BUILTIN;
    case LEAF_TYPE::LF_UNKNOWN:
        break;
    }

    return LF_UNKNOWN;
}

} /* namespace mspdb */