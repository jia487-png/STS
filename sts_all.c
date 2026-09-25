/* ============================================================================
 * sts_all.c — BS IEC 62055-41:2014 STS 工具包 单源文件实现
 *
 * MSVC 编译：
 *   cl /W4 /std:c11 /D_CRT_SECURE_NO_WARNINGS sts_all.c /Fe:sts_toolkit.exe
 * ==========================================================================*/
#define _CRT_SECURE_NO_WARNINGS
#include "sts_all.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* ==========================================================================
 * 1. 状态码字符串
 * ========================================================================== */
const char* sts_status_str(sts_status_t s)
{
    switch (s) {
    case STS_OK:                    return "OK";
    case STS_ERR_INVALID_ARG:       return "INVALID_ARG";
    case STS_ERR_BUFFER_TOO_SMALL:  return "BUFFER_TOO_SMALL";
    case STS_ERR_TABLE_NOT_LOADED:  return "TABLE_NOT_LOADED";
    case STS_ERR_CRC:               return "CRC_ERROR";
    case STS_ERR_MFR_CODE:          return "MFR_CODE_ERROR";
    case STS_ERR_TID_OLD:           return "TID_OLD_ERROR";
    case STS_ERR_TID_USED:          return "TID_USED_ERROR";
    case STS_ERR_KEY_EXPIRED:       return "KEY_EXPIRED_ERROR";
    case STS_ERR_DDTK:              return "DDTK_ERROR";
    case STS_ERR_OVERFLOW:          return "OVERFLOW_ERROR";
    case STS_ERR_KEY_TYPE:          return "KEY_TYPE_ERROR";
    case STS_ERR_FORMAT:            return "FORMAT_ERROR";
    case STS_ERR_RANGE:             return "RANGE_ERROR";
    case STS_ERR_FUNCTION:          return "FUNCTION_ERROR";
    case STS_ERR_CRYPTO:            return "CRYPTO_ERROR";
    case STS_ERR_NOT_IMPLEMENTED:   return "NOT_IMPLEMENTED";
    default:                        return "UNKNOWN";
    }
}

/* ==========================================================================
 * 2. CRC-16 / Luhn
 * ========================================================================== */
u16 sts_crc16(const u8* data, size_t len)
{
    u16 crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (u16)data[i] << 8;
        for (int b = 0; b < 8; ++b) {
            if (crc & 0x8000) crc = (u16)((crc << 1) ^ 0x1021);
            else              crc = (u16)(crc << 1);
        }
    }
    return crc;
}

u16 sts_crc_for_token(const bits66_t* token)
{
    u8 buf[7] = {0};
    u64 lo = token->lo64;
    for (int i = 0; i < 50; ++i) {
        if ((lo >> i) & 1u) {
            int byte_idx = i / 8;
            int bit_idx  = i % 8;
            buf[6 - byte_idx] |= (u8)(1u << bit_idx);
        }
    }
    u64 v = 0;
    for (int i = 0; i < 7; ++i) v = (v << 8) | buf[i];
    v <<= 6;
    u8 final_buf[7];
    for (int i = 6; i >= 0; --i) { final_buf[i] = (u8)(v & 0xFF); v >>= 8; }
    return sts_crc16(final_buf, 7);
}

u8 sts_luhn_check_digit(const char* digits, size_t len)
{
    int sum = 0;
    bool dbl = true;
    for (int i = (int)len - 1; i >= 0; --i) {
        int d = digits[i] - '0';
        if (dbl) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        dbl = !dbl;
    }
    return (u8)((10 - (sum % 10)) % 10);
}

bool sts_luhn_verify(const char* digits, size_t len)
{
    if (len < 2) return false;
    return sts_luhn_check_digit(digits, len - 1) == (u8)(digits[len - 1] - '0');
}

/* ==========================================================================
 * 3. MeterPAN / PANBlock / CONTROLBlock
 * ========================================================================== */
sts_status_t sts_build_drn(const sts_meter_id_t* id, char* out, size_t out_sz)
{
    if (!id || !out) return STS_ERR_INVALID_ARG;
    size_t need = (size_t)id->mfr_code_len + 8 + 1;
    if (out_sz < need) return STS_ERR_BUFFER_TOO_SMALL;
    snprintf(out, out_sz, "%s%s", id->mfr_code, id->dsn);
    return STS_OK;
}

sts_status_t sts_drn_check_digit(const sts_meter_id_t* id, u8* out_digit)
{
    char drn[16];
    sts_status_t s = sts_build_drn(id, drn, sizeof(drn));
    if (s != STS_OK) return s;
    *out_digit = sts_luhn_check_digit(drn, strlen(drn));
    return STS_OK;
}

sts_status_t sts_build_meter_pan(const sts_meter_id_t* id, char pan[19])
{
    if (!id || !pan) return STS_ERR_INVALID_ARG;
    char iain[16];
    if (sts_build_drn(id, iain, sizeof(iain)) != STS_OK) return STS_ERR_INVALID_ARG;
    u8 drn_cd;
    if (sts_drn_check_digit(id, &drn_cd) != STS_OK) return STS_ERR_INVALID_ARG;
    char iin_iain[32];
    int n = snprintf(iin_iain, sizeof(iin_iain), "%s%s%u",
                     id->iin, iain, (unsigned)drn_cd);
    if (n <= 0) return STS_ERR_INVALID_ARG;
    u8 pan_cd = sts_luhn_check_digit(iin_iain, (size_t)n);
    snprintf(pan, 19, "%s%u", iin_iain, (unsigned)pan_cd);
    return STS_OK;
}

sts_status_t sts_build_pan_block(const sts_meter_id_t* id,
                                 bool is_dctk, u64* out_pan_block)
{
    if (!id || !out_pan_block) return STS_ERR_INVALID_ARG;
    char digits[17] = {0};
    if (is_dctk) {
        int take = (id->iin_len > 0) ? (id->iin_len - 1) : 5;
        snprintf(digits, sizeof(digits), "%.*s%011u", take, id->iin, 0u);
    } else if (id->iin_len == 6) {
        char drn[16]; sts_build_drn(id, drn, sizeof(drn));
        snprintf(digits, sizeof(digits), "%.5s%.11s", id->iin + 1, drn);
    } else {
        char drn[16]; sts_build_drn(id, drn, sizeof(drn));
        snprintf(digits, sizeof(digits), "%.3s%.13s", id->iin + 1, drn);
    }
    u64 v = 0;
    for (int i = 0; i < 16; ++i) {
        u8 nib = (u8)(digits[i] - '0');
        v = (v << 4) | nib;
    }
    *out_pan_block = v;
    return STS_OK;
}

sts_status_t sts_build_control_block(u8 kt, u32 sgc, u8 ti, u8 krn,
                                     u64* out_ctrl_block)
{
    if (!out_ctrl_block) return STS_ERR_INVALID_ARG;
    if (kt > 3 || krn < 1 || krn > 9) return STS_ERR_INVALID_ARG;

    u64 v = 0;
    v |= ((u64)(kt & 0xF)) << 60;

    char sgc_s[7];
    snprintf(sgc_s, sizeof(sgc_s), "%06u", sgc);
    for (int i = 0; i < 6; ++i) {
        u8 nib = (u8)(sgc_s[i] - '0');
        v |= ((u64)nib) << (56 - i * 4);
    }

    char ti_s[3];
    snprintf(ti_s, sizeof(ti_s), "%02u", ti);
    v |= ((u64)(ti_s[0] - '0')) << 32;
    v |= ((u64)(ti_s[1] - '0')) << 28;

    v |= ((u64)(krn & 0xF)) << 24;
    v |= 0xFFFFFFull;
    *out_ctrl_block = v;
    return STS_OK;
}

/* ==========================================================================
 * 4. TID
 * ========================================================================== */
bool sts_is_leap_year(int year)
{
    if (year % 400 == 0) return true;
    if (year % 100 == 0) return false;
    return (year % 4) == 0;
}

static const int g_days_in_month[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

static i32 days_from_base(sts_base_date_t base, int year, int month, int day)
{
    int by = 1993, bm = 1, bd = 1;
    if (base == STS_BASE_2014) by = 2014;
    else if (base == STS_BASE_2035) by = 2035;

    i32 days = 0;
    if (year > by) {
        for (int y = by; y < year; ++y)
            days += sts_is_leap_year(y) ? 366 : 365;
    } else if (year < by) {
        for (int y = year; y < by; ++y)
            days -= sts_is_leap_year(y) ? 366 : 365;
    }

    int md_b = 0, md_y = 0;
    for (int m = 0; m < bm - 1; ++m)
        md_b += g_days_in_month[m] + ((m == 1 && sts_is_leap_year(by)) ? 1 : 0);
    for (int m = 0; m < month - 1; ++m)
        md_y += g_days_in_month[m] + ((m == 1 && sts_is_leap_year(year)) ? 1 : 0);

    days += (md_y + day) - (md_b + bd);
    return days;
}

sts_status_t sts_calc_tid(sts_base_date_t base,
                          int year, int month, int day,
                          int hour, int minute, int second, u32* out_tid)
{
    (void)second;
    if (!out_tid) return STS_ERR_INVALID_ARG;
    if (month < 1 || month > 12 || day < 1 || day > 31) return STS_ERR_INVALID_ARG;
    i32 days = days_from_base(base, year, month, day);
    i64 total_min = (i64)days * 1440 + (i64)hour * 60 + minute;
    if (total_min < 0) total_min = 0;
    *out_tid = (u32)(total_min & 0xFFFFFF);
    return STS_OK;
}

bool sts_is_reserved_tid(u32 tid) { return (tid % 1440u) == 1u; }

u32 sts_next_tid_in_minute(u32 tid, u32 seq)
{
    u32 next = tid + seq;
    if (sts_is_reserved_tid(next)) next += 1;
    return next & 0xFFFFFF;
}

/* ==========================================================================
 * 5. 令牌结构
 * ========================================================================== */
u16 sts_encode_transfer_amount(u32 value)
{
    if (value == 0) return 0;
    u32 e = 0;
    u64 scaled = value;
    while (scaled > 0x3FFFu && e < 3) {
        scaled = (scaled + 9) / 10;
        ++e;
    }
    if (scaled > 0x3FFFu) scaled = 0x3FFFu;
    return (u16)(((e & 0x3u) << 14) | (u16)(scaled & 0x3FFFu));
}

u32 sts_decode_transfer_amount(u16 field)
{
    u32 e = (field >> 14) & 0x3u;
    u32 m = field & 0x3FFFu;
    u32 v = m;
    for (u32 i = 0; i < e; ++i) v *= 10;
    return v;
}

sts_status_t sts_token_decode(const bits66_t* raw, sts_token_decoded_t* out)
{
    if (!raw || !out) return STS_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    u64 d = raw->lo64;
    out->token_class = (u8)((d >> 62) & 0x3u);
    out->subclass    = (u8)((d >> 58) & 0xFu);
    out->rnd         = (u8)((d >> 54) & 0xFu);

    if (out->token_class == STS_CLASS_CREDIT) {
        out->tid    = (u32)((d >> 30) & 0xFFFFFFu);
        out->amount = (u16)((d >> 16) & 0xFFFFu);
    } else if (out->token_class == STS_CLASS_METER) {
        out->tid = (u32)((d >> 30) & 0xFFFFFFu);
        switch (out->subclass) {
        case STS_SUB2_SET_MPL:
            out->mpl = (u16)((d >> 16) & 0xFFFFu); break;
        case STS_SUB2_CLEAR_CREDIT:
            out->register_to_clear = (u16)((d >> 16) & 0xFFFFu); break;
        case STS_SUB2_SET_1ST_DEC_KEY:
            out->krn   = (u8)((d >> 24) & 0xFu);
            out->kt    = (u8)((d >> 22) & 0x3u);
            out->kenho = (u8)((d >> 18) & 0xFu);
            out->ro    = (u8)((d >> 17) & 0x1u);
            out->nkho  = (u32)((d >> 1) & 0xFFFFFFFFu);
            break;
        case STS_SUB2_SET_2ND_DEC_KEY:
            out->kenlo = (u8)((d >> 24) & 0xFu);
            out->nklo  = (u32)((d >> 1) & 0xFFFFFFFFu);
            break;
        case STS_SUB2_SET_MPPUL:
            out->mppul = (u16)((d >> 16) & 0xFFFFu); break;
        case STS_SUB2_SET_WM_FACTOR:
            out->wm_factor = (u16)((d >> 16) & 0xFFFFu); break;
        default: break;
        }
    }
    out->crc = (u16)(d & 0xFFFFu);
    return STS_OK;
}

sts_status_t sts_token_encode(const sts_token_decoded_t* in, bits66_t* out)
{
    if (!in || !out) return STS_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    u64 d = 0;
    d |= ((u64)(in->token_class & 0x3u)) << 62;
    d |= ((u64)(in->subclass & 0xFu)) << 58;
    d |= ((u64)(in->rnd & 0xFu)) << 54;

    if (in->token_class == STS_CLASS_CREDIT) {
        d |= ((u64)(in->tid & 0xFFFFFFu)) << 30;
        d |= ((u64)in->amount) << 16;
    } else if (in->token_class == STS_CLASS_METER) {
        d |= ((u64)(in->tid & 0xFFFFFFu)) << 30;
        switch (in->subclass) {
        case STS_SUB2_SET_MPL:
            d |= ((u64)in->mpl) << 16; break;
        case STS_SUB2_CLEAR_CREDIT:
            d |= ((u64)in->register_to_clear) << 16; break;
        case STS_SUB2_SET_1ST_DEC_KEY:
            d |= ((u64)(in->krn & 0xFu)) << 24;
            d |= ((u64)(in->kt  & 0x3u)) << 22;
            d |= ((u64)(in->kenho & 0xFu)) << 18;
            d |= ((u64)(in->ro  & 0x1u)) << 17;
            d |= ((u64)in->nkho) << 1;
            break;
        case STS_SUB2_SET_2ND_DEC_KEY:
            d |= ((u64)(in->kenlo & 0xFu)) << 24;
            d |= ((u64)in->nklo) << 1;
            break;
        case STS_SUB2_SET_MPPUL:
            d |= ((u64)in->mppul) << 16; break;
        case STS_SUB2_SET_WM_FACTOR:
            d |= ((u64)in->wm_factor) << 16; break;
        default: break;
        }
    }

    d &= ~0xFFFFull;
    bits66_t tmp = sts_insert_class_bits(d, in->token_class);
    u16 crc = sts_crc_for_token(&tmp);
    d = (d & ~0xFFFFull) | crc;
    *out = sts_insert_class_bits(d, in->token_class);
    return STS_OK;
}

/* ==========================================================================
 * 6. 2 类位插入/提取
 * ========================================================================== */
bits66_t sts_insert_class_bits(u64 data64, u8 class2)
{
    bits66_t r;
    u8 b28 = (u8)((data64 >> 28) & 1u);
    u8 b27 = (u8)((data64 >> 27) & 1u);
    u64 d = data64 & ~((u64)3u << 27);
    r.hi2 = (u8)(b28 | (b27 << 1));
    r.lo64 = d;
    u8 c_msb = (u8)((class2 >> 1) & 1u);
    u8 c_lsb = (u8)(class2 & 1u);
    r.lo64 |= ((u64)c_msb << 28);
    r.lo64 |= ((u64)c_lsb << 27);
    return r;
}

u8 sts_extract_class_bits(bits66_t in, u64* out_data64)
{
    u8 c_msb = (u8)((in.lo64 >> 28) & 1u);
    u8 c_lsb = (u8)((in.lo64 >> 27) & 1u);
    u8 class2 = (u8)((c_msb << 1) | c_lsb);
    u64 d = in.lo64 & ~((u64)3u << 27);
    d |= ((u64)(in.hi2 & 1u) << 28);
    d |= ((u64)((in.hi2 >> 1) & 1u) << 27);
    *out_data64 = d;
    return class2;
}

/* ==========================================================================
 * 7. DES / TDEA（纯软件实现）
 * ========================================================================== */
static const u8 DES_IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};
static const u8 DES_FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25
};
static const u8 DES_E[48] = {
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1
};
static const u8 DES_P[32] = {
    16,7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2,8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25
};
static const u8 DES_PC1[56] = {
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4
};
static const u8 DES_PC2[48] = {
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,
    23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};
static const u8 DES_SHIFT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const u8 DES_SBOX[8][4][16] = {
    { {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
      {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
      {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
      {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },
    { {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
      {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
      {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
      {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} },
    { {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
      {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
      {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
      {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} },
    { {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
      {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
      {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
      {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} },
    { {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} },
    { {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} },
    { {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
      {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
      {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
      {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} },
    { {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
      {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
      {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
      {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} }
};

static u64 des_permute(const u8* table, int n, u64 in)
{
    u64 out = 0;
    for (int i = 0; i < n; ++i) {
        int src = table[i] - 1;
        u8 bit = (u8)((in >> (64 - 1 - src)) & 1u);
        out = (out << 1) | bit;
    }
    return out;
}

static u32 des_permute32(const u8* table, int n, u32 in)
{
    u32 out = 0;
    for (int i = 0; i < n; ++i) {
        int src = table[i] - 1;
        u8 bit = (u8)((in >> (32 - 1 - src)) & 1u);
        out = (out << 1) | bit;
    }
    return out;
}

static void des_make_subkeys(const u8 key[8], u64 subkeys[16])
{
    u64 k = 0;
    for (int i = 0; i < 8; ++i) k = (k << 8) | key[i];
    u64 pk = des_permute(DES_PC1, 56, k);
    u32 c = (u32)(pk >> 28) & 0x0FFFFFFFu;
    u32 d = (u32)(pk) & 0x0FFFFFFFu;
    for (int i = 0; i < 16; ++i) {
        c = ((c << DES_SHIFT[i]) | (c >> (28 - DES_SHIFT[i]))) & 0x0FFFFFFFu;
        d = ((d << DES_SHIFT[i]) | (d >> (28 - DES_SHIFT[i]))) & 0x0FFFFFFFu;
        u64 cd = ((u64)c << 28) | d;
        subkeys[i] = des_permute(DES_PC2, 48, cd);
    }
}

static u32 des_feistel(u32 r, u64 subkey)
{
    u64 e = des_permute(DES_E, 48, (u64)r << 16);
    e ^= subkey;
    u32 s_out = 0;
    for (int i = 0; i < 8; ++i) {
        u8 six = (u8)((e >> (48 - 6 * (i + 1))) & 0x3Fu);
        u8 row = (u8)(((six & 0x20) >> 4) | (six & 1));
        u8 col = (u8)((six >> 1) & 0x0Fu);
        s_out = (s_out << 4) | DES_SBOX[i][row][col];
    }
    return des_permute32(DES_P, 32, s_out);
}

static void des_block(const u8 key[8], const u8 in[8], u8 out[8], bool enc)
{
    u64 subkeys[16];
    des_make_subkeys(key, subkeys);
    u64 m = 0;
    for (int i = 0; i < 8; ++i) m = (m << 8) | in[i];
    u64 ip = des_permute(DES_IP, 64, m);
    u32 l = (u32)(ip >> 32);
    u32 r = (u32)(ip & 0xFFFFFFFFu);
    for (int i = 0; i < 16; ++i) {
        u64 sk = enc ? subkeys[i] : subkeys[15 - i];
        u32 t = l ^ des_feistel(r, sk);
        l = r; r = t;
    }
    u64 pre = ((u64)r << 32) | l;
    u64 fp  = des_permute(DES_FP, 64, pre);
    for (int i = 0; i < 8; ++i) out[i] = (u8)((fp >> (56 - i * 8)) & 0xFF);
}

void sts_des_set_odd_parity(u8 key[8])
{
    for (int i = 0; i < 8; ++i) {
        u8 b = key[i];
        int ones = 0;
        for (int j = 0; j < 8; ++j) if (b & (1u << j)) ++ones;
        if ((ones & 1) == 0) key[i] ^= 0x01;
    }
}

sts_status_t sts_des_encrypt_block(const u8 key[8], const u8 in[8], u8 out[8])
{
    if (!key || !in || !out) return STS_ERR_INVALID_ARG;
    des_block(key, in, out, true);
    return STS_OK;
}

sts_status_t sts_des_decrypt_block(const u8 key[8], const u8 in[8], u8 out[8])
{
    if (!key || !in || !out) return STS_ERR_INVALID_ARG;
    des_block(key, in, out, false);
    return STS_OK;
}

sts_status_t sts_tdea_encrypt_block(const u8 k1[8], const u8 k2[8],
                                    const u8 in[8], u8 out[8])
{
    u8 t[8]; sts_status_t s;
    s = sts_des_encrypt_block(k1, in, t);  if (s) return s;
    s = sts_des_decrypt_block(k2, t, t);   if (s) return s;
    s = sts_des_encrypt_block(k1, t, out); return s;
}

sts_status_t sts_tdea_decrypt_block(const u8 k1[8], const u8 k2[8],
                                    const u8 in[8], u8 out[8])
{
    u8 t[8]; sts_status_t s;
    s = sts_des_decrypt_block(k1, in, t);  if (s) return s;
    s = sts_des_encrypt_block(k2, t, t);   if (s) return s;
    s = sts_des_decrypt_block(k1, t, out); return s;
}

/* ==========================================================================
 * 8. DKGA
 * ========================================================================== */
sts_status_t sts_dkga_generate(sts_dkga_code_t algo,
                               const u8 vk1[8], const u8 vk2[8],
                               u64 pan_block, u64 ctrl_block,
                               u8 out_decoder_key[8])
{
    if (!vk1 || !out_decoder_key) return STS_ERR_INVALID_ARG;
    u8 data_blk[8], key_blk[8];
    for (int i = 0; i < 8; ++i) {
        data_blk[i] = (u8)((pan_block  >> (i * 8)) & 0xFF);
        key_blk[i]  = (u8)((ctrl_block >> (i * 8)) & 0xFF);
    }
    u8 xored[8];
    for (int i = 0; i < 8; ++i) xored[i] = data_blk[i] ^ key_blk[i];

    switch (algo) {
    case STS_DKGA01: return sts_des_encrypt_block(xored, vk1, out_decoder_key);
    case STS_DKGA02: return sts_des_encrypt_block(vk1, xored, out_decoder_key);
    case STS_DKGA03:
        if (!vk2) return STS_ERR_INVALID_ARG;
        return sts_tdea_encrypt_block(vk1, vk2, xored, out_decoder_key);
    default: return STS_ERR_NOT_IMPLEMENTED;
    }
}

bool sts_dkga01_is_applicable(const char* drn, u32 sgc, u8 kt, u8 krn)
{
    if (!drn) return false;
    if (krn != 1) return false;
    if (kt != 1 && kt != 2 && kt != 3) return false;
    static const u32 sgc_list[] = {100702, 990400, 990401, 990402,
                                   990403, 990404, 990405};
    if (kt == 3) {
        for (size_t i = 0; i < sizeof(sgc_list)/sizeof(sgc_list[0]); ++i)
            if (sgc == sgc_list[i]) return true;
        return false;
    }
    if (drn[0] == '0' && (drn[1] == '1' || drn[1] == '3' ||
                          drn[1] == '4' || drn[1] == '6' ||
                          drn[1] == '7')) return true;
    return false;
}

/* ==========================================================================
 * 9. STA
 * ========================================================================== */
static sts_status_t sta_load_file(const char* path, u8* buf, size_t n)
{
    FILE* f = fopen(path, "rb");
    if (!f) return STS_ERR_TABLE_NOT_LOADED;
    size_t r = fread(buf, 1, n, f);
    fclose(f);
    return (r == n) ? STS_OK : STS_ERR_TABLE_NOT_LOADED;
}

sts_status_t sts_sta_load_tables(const char* sub1, const char* sub2,
                                 const char* perm, sts_sta_tables_t* out)
{
    if (!sub1 || !sub2 || !perm || !out) return STS_ERR_INVALID_ARG;
    sts_status_t s;
    s = sta_load_file(sub1, out->sub_table[0], 16); if (s) return s;
    s = sta_load_file(sub2, out->sub_table[1], 16); if (s) return s;
    s = sta_load_file(perm, out->perm_table, 64);   if (s) return s;
    out->loaded = true;
    return STS_OK;
}

static void sta_substitute(const u8 sub[2][16], u8 key[8], u8 data[8], bool enc)
{
    for (int i = 0; i < 8; ++i) {
        u8 nib = (u8)((data[i] >> 4) & 0xF);
        u8 kn  = (u8)((key[i] >> (enc ? 7 : 3)) & 0x1);
        data[i] = (u8)((sub[kn][nib] << 4) | (data[i] & 0xF));
        nib = (u8)(data[i] & 0xF);
        kn  = (u8)((key[i] >> (enc ? 3 : 7)) & 0x1);
        data[i] = (u8)((data[i] & 0xF0) | sub[kn][nib]);
    }
}

static u64 sta_permute(const u8 perm[64], u64 data, bool enc)
{
    u64 out = 0;
    for (int i = 0; i < 64; ++i) {
        u8 src, dst;
        if (enc) { src = (u8)((data >> i) & 1); dst = perm[i]; }
        else     { src = (u8)((data >> perm[i]) & 1); dst = (u8)i; }
        if (src) out |= ((u64)1 << dst);
    }
    return out;
}

static void sta_rotate_key(u8 key[8], bool left)
{
    u64 k = 0;
    for (int i = 0; i < 8; ++i) k |= ((u64)key[i]) << (i * 8);
    if (left) k = (k << 1) | ((k >> 63) & 1);
    else      k = (k >> 1) | ((k & 1) << 63);
    for (int i = 0; i < 8; ++i) key[i] = (u8)((k >> (i * 8)) & 0xFF);
}

sts_status_t sts_sta_encrypt(const sts_sta_tables_t* tbl,
                             const u8 decoder_key[8],
                             u64 data_block, u64* out_cipher)
{
    if (!tbl || !tbl->loaded || !decoder_key || !out_cipher)
        return STS_ERR_TABLE_NOT_LOADED;
    u8 key[8];
    memcpy(key, decoder_key, 8);
    u64 k = 0;
    for (int i = 0; i < 8; ++i) k |= ((u64)key[i]) << (i * 8);
    k = (k >> 12) | (k << 52);
    for (int i = 0; i < 8; ++i) key[i] = (u8)((k >> (i * 8)) & 0xFF);

    u64 d = data_block;
    for (int r = 0; r < 16; ++r) {
        u8 db[8];
        for (int i = 0; i < 8; ++i) db[i] = (u8)((d >> (i * 8)) & 0xFF);
        sta_substitute(tbl->sub_table, key, db, true);
        d = 0;
        for (int i = 0; i < 8; ++i) d |= ((u64)db[i]) << (i * 8);
        d = sta_permute(tbl->perm_table, d, true);
        sta_rotate_key(key, true);
    }
    *out_cipher = d;
    return STS_OK;
}

sts_status_t sts_sta_decrypt(const sts_sta_tables_t* tbl,
                             const u8 decoder_key[8],
                             u64 cipher_block, u64* out_data)
{
    if (!tbl || !tbl->loaded || !decoder_key || !out_data)
        return STS_ERR_TABLE_NOT_LOADED;
    u8 key[8];
    memcpy(key, decoder_key, 8);
    u64 k = 0;
    for (int i = 0; i < 8; ++i) k |= ((u64)key[i]) << (i * 8);
    k = (k >> 12) | (k << 52);
    for (int i = 0; i < 8; ++i) key[i] = (u8)((k >> (i * 8)) & 0xFF);
    for (int i = 0; i < 16; ++i) sta_rotate_key(key, false);

    u64 d = cipher_block;
    for (int r = 0; r < 16; ++r) {
        d = sta_permute(tbl->perm_table, d, false);
        u8 db[8];
        for (int i = 0; i < 8; ++i) db[i] = (u8)((d >> (i * 8)) & 0xFF);
        sta_substitute(tbl->sub_table, key, db, false);
        d = 0;
        for (int i = 0; i < 8; ++i) d |= ((u64)db[i]) << (i * 8);
        sta_rotate_key(key, false);
    }
    *out_data = d;
    return STS_OK;
}

/* ==========================================================================
 * 10. APDU 序列化
 * ========================================================================== */
sts_status_t sts_apdu_serialize(const sts_apdu_t* apdu,
                                u8* buf, size_t buf_sz, size_t* out_len)
{
    if (!apdu || !buf || !out_len) return STS_ERR_INVALID_ARG;
    if (buf_sz < 19 + 8 + 9) return STS_ERR_BUFFER_TOO_SMALL;
    size_t pos = 0;
    memcpy(buf + pos, apdu->meter_pan, 18); pos += 18;
    buf[pos++] = apdu->tct;
    buf[pos++] = apdu->dkga;
    buf[pos++] = apdu->ea;
    snprintf((char*)(buf + pos), 7, "%06u", apdu->sgc); pos += 6;
    buf[pos++] = apdu->ti;
    buf[pos++] = apdu->krn;
    buf[pos++] = apdu->kt;
    buf[pos++] = apdu->ken;
    for (int i = 0; i < 8; ++i)
        buf[pos++] = (u8)((apdu->token.lo64 >> (i * 8)) & 0xFF);
    buf[pos++] = (u8)(apdu->token.hi2 & 0x3u);
    *out_len = pos;
    return STS_OK;
}

sts_status_t sts_apdu_deserialize(const u8* buf, size_t buf_len,
                                  sts_apdu_t* out_apdu)
{
    if (!buf || !out_apdu) return STS_ERR_INVALID_ARG;
    if (buf_len < 19 + 8 + 9) return STS_ERR_FORMAT;
    memset(out_apdu, 0, sizeof(*out_apdu));
    size_t pos = 0;
    memcpy(out_apdu->meter_pan, buf + pos, 18);
    out_apdu->meter_pan[18] = '\0';
    pos += 18;
    out_apdu->tct  = buf[pos++];
    out_apdu->dkga = buf[pos++];
    out_apdu->ea   = buf[pos++];
    char sgc_s[7];
    memcpy(sgc_s, buf + pos, 6); sgc_s[6] = '\0';
    out_apdu->sgc = (u32)strtoul(sgc_s, NULL, 10);
    pos += 6;
    out_apdu->ti  = buf[pos++];
    out_apdu->krn = buf[pos++];
    out_apdu->kt  = buf[pos++];
    out_apdu->ken = buf[pos++];
    out_apdu->token.lo64 = 0;
    for (int i = 0; i < 8; ++i)
        out_apdu->token.lo64 |= ((u64)buf[pos++]) << (i * 8);
    out_apdu->token.hi2 = buf[pos++] & 0x3u;
    return STS_OK;
}

/* ==========================================================================
 * 11. TCDU（IEC 62055-51 数字载体）
 * ========================================================================== */
static void token66_to_decimal12(bits66_t tok, u8 d[12])
{
    u64 lo = tok.lo64;
    u8  hi = (u8)(tok.hi2 & 0x3u);
    u64 part1 = ((u64)hi << 48) | (lo >> 2);
    u64 part2 = (lo >> 16) & 0xFFFFFu;
    u64 part3 = lo & 0xFFFFu;

    d[0] = (u8)((part1 / 1000u) % 10);
    d[1] = (u8)((part1 / 100u)  % 10);
    d[2] = (u8)((part1 / 10u)   % 10);
    d[3] = (u8)(part1 % 10);
    d[4] = (u8)((part2 / 1000u) % 10);
    d[5] = (u8)((part2 / 100u)  % 10);
    d[6] = (u8)((part2 / 10u)   % 10);
    d[7] = (u8)(part2 % 10);
    d[8]  = (u8)((part3 / 1000u) % 10);
    d[9]  = (u8)((part3 / 100u)  % 10);
    d[10] = (u8)((part3 / 10u)   % 10);
    d[11] = (u8)(part3 % 10);
}

static bits66_t decimal12_to_token66(const u8 d[12])
{
    u64 part1 = (u64)d[0]*1000 + d[1]*100 + d[2]*10 + d[3];
    u64 part2 = (u64)d[4]*1000 + d[5]*100 + d[6]*10 + d[7];
    u64 part3 = (u64)d[8]*1000 + d[9]*100 + d[10]*10 + d[11];
    u64 lo = 0;
    lo |= (part3 & 0xFFFFu);
    lo |= ((part2 & 0xFFFFFu) << 16);
    lo |= ((part1 & 0x3FFFFFFFu) << 36);
    bits66_t tok;
    tok.lo64 = lo;
    tok.hi2  = (u8)((part1 >> 30) & 0x3u);
    return tok;
}

static void sgc_to_3digits(u32 sgc, u8 out[3])
{
    out[0] = (u8)((sgc / 100u) % 20);
    out[1] = (u8)((sgc / 10u)  % 10);
    out[2] = (u8)(sgc % 10);
}

static u32 digits3_to_sgc(const u8 d[3])
{
    return (u32)d[0]*100 + (u32)d[1]*10 + (u32)d[2];
}

sts_status_t sts_tcdu_digital_encode(const sts_apdu_t* apdu,
                                     sts_tcdu_digital_t* out)
{
    if (!apdu || !out) return STS_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->digits[0] = 0;
    out->digits[1] = 1;
    out->digits[2] = (u8)(apdu->ea % 10);
    out->digits[3] = (u8)(apdu->tct % 10);
    u8 tokd[12];
    token66_to_decimal12(apdu->token, tokd);
    for (int i = 0; i < 12; ++i) out->digits[4 + i] = tokd[i];
    u8 sgc3[3];
    sgc_to_3digits(apdu->sgc, sgc3);
    out->digits[16] = sgc3[0];
    out->digits[17] = sgc3[1];
    out->digits[18] = sgc3[2];
    char buf[STS_TCDU_DIGITS + 1];
    for (int i = 0; i < 19; ++i) buf[i] = (char)('0' + out->digits[i]);
    buf[19] = '\0';
    out->digits[19] = sts_luhn_check_digit(buf, 19);
    return STS_OK;
}

sts_status_t sts_tcdu_digital_decode(const sts_tcdu_digital_t* in,
                                     sts_apdu_t* out_apdu)
{
    if (!in || !out_apdu) return STS_ERR_INVALID_ARG;
    if (in->digits[0] != 0 || in->digits[1] != 1) return STS_ERR_FORMAT;
    char buf[STS_TCDU_DIGITS + 1];
    for (int i = 0; i < STS_TCDU_DIGITS; ++i) buf[i] = (char)('0' + in->digits[i]);
    buf[STS_TCDU_DIGITS] = '\0';
    if (!sts_luhn_verify(buf, STS_TCDU_DIGITS)) return STS_ERR_CRC;
    memset(out_apdu, 0, sizeof(*out_apdu));
    out_apdu->ea  = in->digits[2];
    out_apdu->tct = in->digits[3];
    u8 tokd[12];
    for (int i = 0; i < 12; ++i) tokd[i] = in->digits[4 + i];
    out_apdu->token = decimal12_to_token66(tokd);
    u8 sgc3[3] = { in->digits[16], in->digits[17], in->digits[18] };
    out_apdu->sgc = digits3_to_sgc(sgc3);
    out_apdu->dkga = 0;
    out_apdu->ti   = 0;
    out_apdu->krn  = 0;
    out_apdu->kt   = 0;
    out_apdu->ken  = 0;
    out_apdu->meter_pan[0] = '\0';
    return STS_OK;
}

void sts_tcdu_digital_to_string(const sts_tcdu_digital_t* t,
                                char out[STS_TCDU_DIGITS + 1])
{
    if (!t || !out) return;
    for (int i = 0; i < STS_TCDU_DIGITS; ++i)
        out[i] = (char)('0' + t->digits[i]);
    out[STS_TCDU_DIGITS] = '\0';
}

sts_status_t sts_tcdu_digital_from_string(const char* s,
                                          sts_tcdu_digital_t* out)
{
    if (!s || !out) return STS_ERR_INVALID_ARG;
    if (strlen(s) != STS_TCDU_DIGITS) return STS_ERR_FORMAT;
    for (int i = 0; i < STS_TCDU_DIGITS; ++i) {
        if (s[i] < '0' || s[i] > '9') return STS_ERR_FORMAT;
        out->digits[i] = (u8)(s[i] - '0');
    }
    return STS_OK;
}

/* ==========================================================================
 * 12. POS 端
 * ========================================================================== */
static sts_status_t pos_make_decoder_key(sts_pos_ctx_t* ctx,
                                         u64 pan_block, u64 ctrl_block,
                                         u8 out_key[8])
{
    return sts_dkga_generate(ctx->dkga, ctx->vk1, ctx->vk2,
                             pan_block, ctrl_block, out_key);
}

static sts_status_t pos_build_blocks(sts_pos_ctx_t* ctx,
                                     u64* pan_block, u64* ctrl_block)
{
    sts_status_t s;
    s = sts_build_pan_block(&ctx->meter_id, false, pan_block);
    if (s != STS_OK) return s;
    s = sts_build_control_block(ctx->kt, ctx->sgc, ctx->ti, ctx->krn, ctrl_block);
    return s;
}

static sts_status_t pos_encrypt_token(sts_pos_ctx_t* ctx,
                                      const u8 decoder_key[8],
                                      bits66_t* token)
{
    u64 data64;
    u8 cls = sts_extract_class_bits(*token, &data64);
    u64 cipher = 0;

    if (ctx->ea == 7) {
        sts_status_t s = sts_sta_encrypt(&ctx->sta_tables, decoder_key,
                                         data64, &cipher);
        if (s != STS_OK) return s;
    } else if (ctx->ea == 9) {
        u8 key[8], in[8], out[8];
        memcpy(key, decoder_key, 8);
        sts_des_set_odd_parity(key);
        for (int i = 0; i < 8; ++i) in[i] = (u8)((data64 >> (i * 8)) & 0xFF);
        sts_status_t s = sts_des_encrypt_block(key, in, out);
        if (s != STS_OK) return s;
        for (int i = 0; i < 8; ++i) cipher |= ((u64)out[i]) << (i * 8);
    } else {
        return STS_ERR_NOT_IMPLEMENTED;
    }

    *token = sts_insert_class_bits(cipher, cls);
    return STS_OK;
}

static void pos_fill_apdu_common(const sts_pos_ctx_t* ctx, sts_apdu_t* apdu)
{
    sts_build_meter_pan(&ctx->meter_id, apdu->meter_pan);
    apdu->tct  = ctx->tct;
    apdu->dkga = (u8)ctx->dkga;
    apdu->ea   = ctx->ea;
    apdu->sgc  = ctx->sgc;
    apdu->ti   = ctx->ti;
    apdu->krn  = ctx->krn;
    apdu->kt   = ctx->kt;
    apdu->ken  = ctx->ken;
    memset(&apdu->token, 0, sizeof(apdu->token));
}

sts_status_t sts_pos_init(sts_pos_ctx_t* ctx)
{
    if (!ctx) return STS_ERR_INVALID_ARG;
    memset(ctx, 0, sizeof(*ctx));
    ctx->ea   = 9;
    ctx->dkga = STS_DKGA02;
    ctx->krn  = 1;
    ctx->kt   = 2;
    ctx->ken  = 255;
    ctx->tct  = 2;
    return STS_OK;
}

sts_status_t sts_pos_make_transfer_credit(sts_pos_ctx_t* ctx,
                                          u32 value,
                                          sts_credit_subclass_t subclass,
                                          u32 tid,
                                          sts_apdu_t* out_apdu)
{
    if (!ctx || !out_apdu) return STS_ERR_INVALID_ARG;
    if (subclass > STS_SUB_CURRENCY) return STS_ERR_INVALID_ARG;
    if (sts_is_reserved_tid(tid)) tid += 1;

    sts_token_decoded_t t;
    memset(&t, 0, sizeof(t));
    t.token_class = STS_CLASS_CREDIT;
    t.subclass    = (u8)subclass;
    t.rnd         = (u8)(tid & 0xFu);
    t.tid         = tid & 0xFFFFFFu;
    t.amount      = sts_encode_transfer_amount(value);

    bits66_t tok;
    sts_status_t s = sts_token_encode(&t, &tok);
    if (s != STS_OK) return s;

    u64 pan_block, ctrl_block;
    s = pos_build_blocks(ctx, &pan_block, &ctrl_block); if (s) return s;
    u8 dk[8];
    s = pos_make_decoder_key(ctx, pan_block, ctrl_block, dk); if (s) return s;
    s = pos_encrypt_token(ctx, dk, &tok); if (s) return s;

    pos_fill_apdu_common(ctx, out_apdu);
    out_apdu->token = tok;
    return STS_OK;
}

sts_status_t sts_pos_make_test_display(sts_pos_ctx_t* ctx,
                                       u8 subclass, u32 control,
                                       u16 mfr_code, u32 tid,
                                       sts_apdu_t* out_apdu)
{
    if (!ctx || !out_apdu) return STS_ERR_INVALID_ARG;
    if (subclass > 15) return STS_ERR_INVALID_ARG;
    if (sts_is_reserved_tid(tid)) tid += 1;

    u64 d = 0;
    d |= ((u64)1u) << 62;
    d |= ((u64)(subclass & 0xFu)) << 58;
    d |= ((u64)(tid & 0xFFFFFFu)) << 20;
    d |= ((u64)(control & 0xFFFFFu)) << 12;
    d |= ((u64)(mfr_code & 0xFFFFu)) << 12;

    bits66_t tok = sts_insert_class_bits(d, 1);
    u16 crc = sts_crc_for_token(&tok);
    d &= ~0xFFFFull;
    d |= crc;
    tok = sts_insert_class_bits(d, 1);

    pos_fill_apdu_common(ctx, out_apdu);
    out_apdu->token = tok;
    return STS_OK;
}

sts_status_t sts_pos_make_class2(sts_pos_ctx_t* ctx,
                                 u8 subclass, u32 tid,
                                 const sts_token_decoded_t* params,
                                 sts_apdu_t* out_apdu)
{
    if (!ctx || !out_apdu || !params) return STS_ERR_INVALID_ARG;
    if (subclass > 15) return STS_ERR_INVALID_ARG;
    if (sts_is_reserved_tid(tid)) tid += 1;

    sts_token_decoded_t t = *params;
    t.token_class = STS_CLASS_METER;
    t.subclass    = subclass;
    t.tid         = tid & 0xFFFFFFu;
    t.rnd         = (u8)(tid & 0xFu);

    bits66_t tok;
    sts_status_t s = sts_token_encode(&t, &tok); if (s) return s;

    u64 pan_block, ctrl_block;
    s = pos_build_blocks(ctx, &pan_block, &ctrl_block); if (s) return s;
    u8 dk[8];
    s = pos_make_decoder_key(ctx, pan_block, ctrl_block, dk); if (s) return s;
    s = pos_encrypt_token(ctx, dk, &tok); if (s) return s;

    pos_fill_apdu_common(ctx, out_apdu);
    out_apdu->token = tok;
    return STS_OK;
}

sts_status_t sts_pos_make_key_change_pair(sts_pos_ctx_t* ctx,
                                          const sts_meter_id_t* new_id,
                                          u32 new_sgc, u8 new_ti,
                                          u8 new_krn, u8 new_kt,
                                          u8 new_ken, u32 tid,
                                          sts_apdu_t* out_1st,
                                          sts_apdu_t* out_2nd)
{
    if (!ctx || !out_1st || !out_2nd || !new_id) return STS_ERR_INVALID_ARG;
    if (new_krn < 1 || new_krn > 9) return STS_ERR_INVALID_ARG;
    if (new_kt > 3) return STS_ERR_INVALID_ARG;
    if (sts_is_reserved_tid(tid)) tid += 1;

    u64 new_pan, new_ctrl;
    sts_build_pan_block(new_id, false, &new_pan);
    sts_build_control_block(new_kt, new_sgc, new_ti, new_krn, &new_ctrl);

    u8 new_dk[8];
    sts_status_t s = sts_dkga_generate(ctx->dkga, ctx->vk1, ctx->vk2,
                                       new_pan, new_ctrl, new_dk);
    if (s != STS_OK) return s;

    u32 nkho = (u32)(((u64)new_dk[0] << 24) | ((u64)new_dk[1] << 16) |
                     ((u64)new_dk[2] << 8)  |  (u64)new_dk[4]);
    u32 nklo = (u32)(((u64)new_dk[3] << 24) | ((u64)new_dk[5] << 16) |
                     ((u64)new_dk[6] << 8)  |  (u64)new_dk[7]);

    sts_token_decoded_t t1;
    memset(&t1, 0, sizeof(t1));
    t1.token_class = STS_CLASS_METER;
    t1.subclass    = STS_SUB2_SET_1ST_DEC_KEY;
    t1.tid         = tid & 0xFFFFFFu;
    t1.rnd         = (u8)(tid & 0xFu);
    t1.krn         = new_krn;
    t1.kt          = new_kt;
    t1.kenho       = (u8)((new_ken >> 4) & 0xFu);
    t1.ro          = 0;
    t1.nkho        = nkho;

    bits66_t tok1;
    s = sts_token_encode(&t1, &tok1); if (s) return s;

    u32 tid2 = (tid + 1) & 0xFFFFFFu;
    if (sts_is_reserved_tid(tid2)) tid2 += 1;

    sts_token_decoded_t t2;
    memset(&t2, 0, sizeof(t2));
    t2.token_class = STS_CLASS_METER;
    t2.subclass    = STS_SUB2_SET_2ND_DEC_KEY;
    t2.tid         = tid2;
    t2.rnd         = (u8)(tid2 & 0xFu);
    t2.kenlo       = (u8)(new_ken & 0xFu);
    t2.nklo        = nklo;

    bits66_t tok2;
    s = sts_token_encode(&t2, &tok2); if (s) return s;

    u64 pan_block, ctrl_block;
    s = pos_build_blocks(ctx, &pan_block, &ctrl_block); if (s) return s;
    u8 cur_dk[8];
    s = pos_make_decoder_key(ctx, pan_block, ctrl_block, cur_dk); if (s) return s;
    s = pos_encrypt_token(ctx, cur_dk, &tok1); if (s) return s;
    s = pos_encrypt_token(ctx, cur_dk, &tok2); if (s) return s;

    pos_fill_apdu_common(ctx, out_1st);
    out_1st->token = tok1;
    pos_fill_apdu_common(ctx, out_2nd);
    out_2nd->token = tok2;
    return STS_OK;
}

sts_status_t sts_pos_apdu_to_token_data(const sts_apdu_t* apdu,
                                        bits66_t* out_token_data)
{
    if (!apdu || !out_token_data) return STS_ERR_INVALID_ARG;
    *out_token_data = apdu->token;
    return STS_OK;
}

/* ==========================================================================
 * 13. Meter 端
 * ========================================================================== */
void sts_tid_store_init(sts_tid_store_t* s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->oldest = 0xFFFFFFFFu;
}

bool sts_tid_store_contains(const sts_tid_store_t* s, u32 tid)
{
    if (!s) return false;
    for (size_t i = 0; i < s->count; ++i)
        if (s->tids[i] == tid) return true;
    return false;
}

void sts_tid_store_insert(sts_tid_store_t* s, u32 tid)
{
    if (!s) return;
    if (s->count < STS_TID_HISTORY) {
        s->tids[s->count++] = tid;
    } else {
        size_t oldest_idx = 0;
        for (size_t i = 1; i < s->count; ++i)
            if (s->tids[i] < s->tids[oldest_idx]) oldest_idx = i;
        s->tids[oldest_idx] = tid;
    }
    u32 mn = 0xFFFFFFFFu;
    for (size_t i = 0; i < s->count; ++i)
        if (s->tids[i] < mn) mn = s->tids[i];
    s->oldest = mn;
}

void sts_tid_store_clear(sts_tid_store_t* s)
{
    if (!s) return;
    memset(s->tids, 0, sizeof(s->tids));
    s->count = 0;
    s->head = 0;
    s->oldest = 0xFFFFFFFFu;
}

static u64 mono_ms(void)
{
#ifdef _WIN32
    return (u64)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000ull + (u64)(ts.tv_nsec / 1000000);
#endif
}

bool sts_key_type_change_allowed(u8 parent_kt, u8 child_kt, u8 tct)
{
    static const u8 table[4][4] = {
        { 1, 1, 1, 0 },
        { 0, 1, 1, 0 },
        { 0, 1, 1, 0 },
        { 0, 1, 1, 1 }
    };
    if (parent_kt > 3 || child_kt > 3) return false;
    if ((parent_kt == 3 || child_kt == 3) && tct != 1) return false;
    return table[parent_kt][child_kt] != 0;
}

sts_status_t sts_meter_apply_kct(sts_meter_ctx_t* ctx,
                                 const sts_token_decoded_t* tok,
                                 u64 now, bool* out_applied)
{
    if (!ctx || !tok || !out_applied) return STS_ERR_INVALID_ARG;
    *out_applied = false;
    sts_kct_staging_t* s = &ctx->kct_staging;

    if (s->active) {
        u64 elapsed = now - s->first_seen_ms;
        if (elapsed > 10ull * 60ull * 1000ull) {
            memset(s, 0, sizeof(*s));
        }
    }
    if (!s->active) {
        s->active        = true;
        s->first_seen_ms = now;
    }

    if (tok->subclass == STS_SUB2_SET_1ST_DEC_KEY) {
        s->have_1st = true;
        s->nkho[0]  = (u8)(tok->nkho >> 24);
        s->nkho[1]  = (u8)(tok->nkho >> 16);
        s->nkho[2]  = (u8)(tok->nkho >>  8);
        s->nkho[3]  = (u8)(tok->nkho      );
        s->new_krn  = tok->krn;
        s->new_kt   = tok->kt;
        s->new_ken  = (u8)((tok->kenho << 4) | (s->new_ken & 0x0F));
        s->ro       = tok->ro;
        s->tid_1st  = tok->tid;
    } else if (tok->subclass == STS_SUB2_SET_2ND_DEC_KEY) {
        s->have_2nd = true;
        s->nklo[0]  = (u8)(tok->nklo >> 24);
        s->nklo[1]  = (u8)(tok->nklo >> 16);
        s->nklo[2]  = (u8)(tok->nklo >>  8);
        s->nklo[3]  = (u8)(tok->nklo      );
        s->new_ken  = (u8)((s->new_ken & 0xF0) | (tok->kenlo & 0x0F));
        s->tid_2nd  = tok->tid;
    } else {
        return STS_ERR_INVALID_ARG;
    }

    if (!(s->have_1st && s->have_2nd)) return STS_OK;

    if (!sts_key_type_change_allowed(ctx->dkr.kt, s->new_kt, ctx->tct))
        return STS_ERR_KEY_TYPE;

    u8 new_dk[8];
    new_dk[0] = s->nkho[0]; new_dk[1] = s->nkho[1];
    new_dk[2] = s->nkho[2]; new_dk[3] = s->nkho[3];
    new_dk[4] = s->nklo[0]; new_dk[5] = s->nklo[1];
    new_dk[6] = s->nklo[2]; new_dk[7] = s->nklo[3];

    memcpy(ctx->dkr.decoder_key, new_dk, 8);
    ctx->dkr.krn = s->new_krn;
    ctx->dkr.kt  = s->new_kt;
    ctx->dkr.ti  = s->new_ti;
    ctx->dkr.ken = s->new_ken;

    if (s->ro) sts_tid_store_clear(&ctx->tid_store);
    sts_tid_store_insert(&ctx->tid_store, s->tid_1st);
    sts_tid_store_insert(&ctx->tid_store, s->tid_2nd);

    memset(s, 0, sizeof(*s));
    *out_applied = true;
    return STS_OK;
}

sts_status_t sts_meter_init(sts_meter_ctx_t* ctx)
{
    if (!ctx) return STS_ERR_INVALID_ARG;
    memset(ctx, 0, sizeof(*ctx));
    ctx->ea = 9;
    ctx->tct = 2;
    ctx->key_expiry_enabled = false;
    sts_tid_store_init(&ctx->tid_store);
    ctx->kct_staging.active = false;
    return STS_OK;
}

static sts_status_t meter_decrypt_token(sts_meter_ctx_t* ctx,
                                        const bits66_t* token,
                                        u64* out_data64)
{
    u64 data64;
    (void)sts_extract_class_bits(*token, &data64);

    if (ctx->ea == 7) {
        u64 plain = 0;
        sts_status_t s = sts_sta_decrypt(&ctx->sta_tables,
                                         ctx->dkr.decoder_key,
                                         data64, &plain);
        if (s != STS_OK) return s;
        *out_data64 = plain;
    } else if (ctx->ea == 9) {
        u8 key[8], in[8], out[8];
        memcpy(key, ctx->dkr.decoder_key, 8);
        sts_des_set_odd_parity(key);
        for (int i = 0; i < 8; ++i) in[i] = (u8)((data64 >> (i * 8)) & 0xFF);
        sts_status_t s = sts_des_decrypt_block(key, in, out);
        if (s != STS_OK) return s;
        u64 plain = 0;
        for (int i = 0; i < 8; ++i) plain |= ((u64)out[i]) << (i * 8);
        *out_data64 = plain;
    } else {
        return STS_ERR_NOT_IMPLEMENTED;
    }
    return STS_OK;
}

static void meter_authenticate(const bits66_t* token, u8 token_class,
                               sts_auth_result_t* out)
{
    (void)token_class;
    memset(out, 0, sizeof(*out));
    out->authentic = true;
    bits66_t tmp = *token;
    tmp.lo64 &= ~0xFFFFull;
    u16 calc = sts_crc_for_token(&tmp);
    u16 recv = (u16)(token->lo64 & 0xFFFFu);
    if (calc != recv) {
        out->authentic = false;
        out->crc_error = true;
    }
}

static void meter_validate(sts_meter_ctx_t* ctx, u8 token_class, u32 tid,
                           bool has_tid, sts_valid_result_t* out)
{
    memset(out, 0, sizeof(*out));
    out->valid = true;
    if (!has_tid) return;
    if (tid < ctx->tid_store.oldest) {
        out->valid = false; out->old_error = true; return;
    }
    if (sts_tid_store_contains(&ctx->tid_store, tid)) {
        out->valid = false; out->used_error = true; return;
    }
    if (ctx->key_expiry_enabled) {
        u8 tid_hi = (u8)((tid >> 16) & 0xFFu);
        if (tid_hi > ctx->dkr.ken) {
            out->valid = false; out->key_expired_error = true; return;
        }
    }
    if (token_class == 0 && ctx->dkr.kt == 1) {
        out->valid = false; out->ddtk_error = true; return;
    }
}

sts_status_t sts_meter_parse(sts_meter_ctx_t* ctx,
                             const bits66_t* token_data,
                             sts_meter_parse_result_t* out)
{
    if (!ctx || !token_data || !out) return STS_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    u64 cipher64;
    u8 cls = sts_extract_class_bits(*token_data, &cipher64);

    if (cls == 1) {
        out->is_class1 = true;
        u64 d = cipher64;
        out->class1.token_class = 1;
        out->class1.subclass    = (u8)((d >> 58) & 0xFu);
        out->class1.control     = (u32)((d >> 16) & 0xFFFFFFFFu);
        out->class1.mfr_code    = (u16)((d >> 32) & 0xFFFFu);
        out->class1.crc         = (u16)(d & 0xFFFFu);

        bits66_t tmp = *token_data;
        tmp.lo64 &= ~0xFFFFull;
        u16 calc = sts_crc_for_token(&tmp);
        out->auth.authentic = (calc == out->class1.crc);
        out->auth.crc_error = !out->auth.authentic;
        if (!out->auth.authentic) {
            out->result = STS_TOKEN_FORMAT_ERROR;
            return STS_OK;
        }
        out->valid.valid = true;
        out->result = STS_TOKEN_ACCEPT;
        return STS_OK;
    }

    u64 plain64 = 0;
    sts_status_t s = meter_decrypt_token(ctx, token_data, &plain64);
    if (s != STS_OK) return s;

    bits66_t plain66 = sts_insert_class_bits(plain64, cls);
    sts_token_decode(&plain66, &out->decoded);

    meter_authenticate(&plain66, cls, &out->auth);
    if (!out->auth.authentic) {
        out->result = STS_TOKEN_FORMAT_ERROR;
        return STS_OK;
    }

    meter_validate(ctx, cls, out->decoded.tid, true, &out->valid);
    if (!out->valid.valid) {
        out->result = STS_TOKEN_FUNCTION_ERROR;
        return STS_OK;
    }

    if (cls == 2 &&
        (out->decoded.subclass == STS_SUB2_SET_1ST_DEC_KEY ||
         out->decoded.subclass == STS_SUB2_SET_2ND_DEC_KEY)) {
        bool applied = false;
        sts_status_t ks = sts_meter_apply_kct(ctx, &out->decoded,
                                              mono_ms(), &applied);
        if (ks == STS_ERR_KEY_TYPE) {
            out->result = STS_TOKEN_KEY_TYPE_ERROR;
            return STS_OK;
        }
        if (ks != STS_OK) {
            out->result = STS_TOKEN_FUNCTION_ERROR;
            return STS_OK;
        }
        if (applied) {
            out->result = STS_TOKEN_ACCEPT;
        } else if (out->decoded.subclass == STS_SUB2_SET_1ST_DEC_KEY) {
            out->result = STS_TOKEN_1ST_KCT;
        } else {
            out->result = STS_TOKEN_2ND_KCT;
        }
        return STS_OK;
    }

    out->result = STS_TOKEN_ACCEPT;
    sts_tid_store_insert(&ctx->tid_store, out->decoded.tid);
    return STS_OK;
}

/* ==========================================================================
 * 14. 一致性测试
 * ========================================================================== */
static void add_case(sts_conformance_report_t* r,
                     const char* name, bool passed, const char* detail)
{
    if (r->count >= 128) return;
    sts_test_case_t* c = &r->cases[r->count++];
    strncpy(c->name, name ? name : "?", sizeof(c->name) - 1);
    c->name[sizeof(c->name) - 1] = '\0';
    c->passed = passed;
    strncpy(c->detail, detail ? detail : "", sizeof(c->detail) - 1);
    c->detail[sizeof(c->detail) - 1] = '\0';
    if (passed) ++r->passed; else ++r->failed;
}

static void test_tid(sts_conformance_report_t* r)
{
    u32 t = 0;
    sts_calc_tid(STS_BASE_1993, 1993, 1, 1, 0, 1, 45, &t);
    add_case(r, "TID_1993_01_01_00_01_45", t == 1, "expect 1");
    sts_calc_tid(STS_BASE_1993, 1996, 3, 25, 13, 55, 22, &t);
    add_case(r, "TID_1996_03_25_13_55_22", t == 1698595, "expect 1698595");
    sts_calc_tid(STS_BASE_1993, 2005, 11, 1, 0, 1, 55, &t);
    add_case(r, "TID_2005_11_01_00_01_55", t == 6749281, "expect 6749281");
    sts_calc_tid(STS_BASE_2014, 2015, 12, 1, 0, 1, 5, &t);
    add_case(r, "TID_2015_12_01_00_01_05", t == 1005121, "expect 1005121");
    add_case(r, "TID_reserved_00h01", sts_is_reserved_tid(1), "");
    add_case(r, "TID_reserved_1441",  sts_is_reserved_tid(1441), "");
    add_case(r, "leap_2000", sts_is_leap_year(2000), "");
    add_case(r, "not_leap_1900", !sts_is_leap_year(1900), "");
}

static void test_crc(sts_conformance_report_t* r)
{
    const u8 v[] = "123456789";
    u16 c = sts_crc16(v, 9);
    add_case(r, "CRC16_123456789", c == 0x29B1, "expect 0x29B1");
    u16 e = sts_crc16(NULL, 0);
    add_case(r, "CRC16_empty", e == 0xFFFF, "expect 0xFFFF");
    bits66_t tok; tok.lo64 = 0x123456789ABCDEF0ull; tok.hi2 = 0;
    u16 a = sts_crc_for_token(&tok);
    u16 b = sts_crc_for_token(&tok);
    add_case(r, "CRC_token_deterministic", a == b, "");
}

static void test_luhn(sts_conformance_report_t* r)
{
    add_case(r, "Luhn_79927398713",  sts_luhn_verify("79927398713", 11), "");
    add_case(r, "Luhn_79927398710", !sts_luhn_verify("79927398710", 11), "");
    u8 cd = sts_luhn_check_digit("7992739871", 10);
    add_case(r, "Luhn_cd_7992739871", cd == 3, "expect 3");
}

static void test_bitfield(sts_conformance_report_t* r)
{
    u64 data = 0x6543210098765432ull;
    for (u8 cls = 0; cls < 4; ++cls) {
        bits66_t t = sts_insert_class_bits(data, cls);
        u64 back = 0;
        u8 c2 = sts_extract_class_bits(t, &back);
        char name[64];
        snprintf(name, sizeof(name), "bitfield_roundtrip_cls%u", cls);
        add_case(r, name, c2 == cls && back == data, "");
    }
}

static void test_amount(sts_conformance_report_t* r)
{
    add_case(r, "amount_0", sts_encode_transfer_amount(0) == 0, "");
    add_case(r, "amount_1", sts_encode_transfer_amount(1) == 1, "");
    add_case(r, "amount_rt_1",
             sts_decode_transfer_amount(sts_encode_transfer_amount(1)) == 1, "");
    add_case(r, "amount_rt_16383",
             sts_decode_transfer_amount(sts_encode_transfer_amount(16383)) == 16383, "");
}

sts_status_t sts_conformance_roundtrip(sts_pos_ctx_t* pos,
                                       sts_meter_ctx_t* meter,
                                       u32 value,
                                       sts_credit_subclass_t subclass,
                                       u32 tid,
                                       sts_test_case_t* out_case)
{
    if (!pos || !meter || !out_case) return STS_ERR_INVALID_ARG;
    sts_apdu_t apdu;
    sts_status_t s = sts_pos_make_transfer_credit(pos, value, subclass, tid, &apdu);
    if (s != STS_OK) {
        strncpy(out_case->name, "roundtrip_gen", sizeof(out_case->name) - 1);
        out_case->passed = false;
        snprintf(out_case->detail, sizeof(out_case->detail),
                 "POS 生成失败: %s", sts_status_str(s));
        return s;
    }
    sts_meter_parse_result_t res;
    s = sts_meter_parse(meter, &apdu.token, &res);
    if (s != STS_OK) {
        strncpy(out_case->name, "roundtrip_parse", sizeof(out_case->name) - 1);
        out_case->passed = false;
        snprintf(out_case->detail, sizeof(out_case->detail),
                 "Meter 解析失败: %s", sts_status_str(s));
        return s;
    }
    strncpy(out_case->name, "roundtrip_transfer_credit",
            sizeof(out_case->name) - 1);
    out_case->name[sizeof(out_case->name) - 1] = '\0';

    if (res.result != STS_TOKEN_ACCEPT) {
        out_case->passed = false;
        snprintf(out_case->detail, sizeof(out_case->detail),
                 "结果非 ACCEPT (result=%d)", (int)res.result);
        return STS_OK;
    }
    if (res.decoded.token_class != STS_CLASS_CREDIT ||
        res.decoded.subclass != (u8)subclass) {
        out_case->passed = false;
        snprintf(out_case->detail, sizeof(out_case->detail), "Class/SubClass 不匹配");
        return STS_OK;
    }
    u32 decoded_val = sts_decode_transfer_amount(res.decoded.amount);
    if (decoded_val != value) {
        out_case->passed = false;
        snprintf(out_case->detail, sizeof(out_case->detail),
                 "金额不匹配: 期望 %u 实际 %u", value, decoded_val);
        return STS_OK;
    }
    out_case->passed = true;
    snprintf(out_case->detail, sizeof(out_case->detail),
             "value=%u tid=%u", value, res.decoded.tid);
    return STS_OK;
}

sts_status_t sts_conformance_run_all(sts_conformance_report_t* report)
{
    if (!report) return STS_ERR_INVALID_ARG;
    memset(report, 0, sizeof(*report));

    test_tid(report);
    test_crc(report);
    test_luhn(report);
    test_bitfield(report);
    test_amount(report);

    sts_pos_ctx_t pos;
    sts_meter_ctx_t meter;
    memset(&pos, 0, sizeof(pos));
    memset(&meter, 0, sizeof(meter));

    pos.meter_id.iin_len = 4;
    strcpy(pos.meter_id.iin, "0000");
    pos.meter_id.mfr_code_len = 4;
    strcpy(pos.meter_id.mfr_code, "1234");
    strcpy(pos.meter_id.dsn, "00000001");
    pos.sgc  = 100702;
    pos.ti   = 1;
    pos.krn  = 1;
    pos.kt   = 2;
    pos.ken  = 255;
    pos.dkga = STS_DKGA02;
    pos.ea   = 9;
    pos.tct  = 2;
    memset(pos.vk1, 0x11, 8);
    memset(pos.vk2, 0x22, 8);

    meter.meter_id = pos.meter_id;
    meter.ea = 9;
    meter.tct = 2;
    meter.dkr.ti  = pos.ti;
    meter.dkr.krn = pos.krn;
    meter.dkr.kt  = pos.kt;
    meter.dkr.ken = pos.ken;

    u64 pan, ctrl;
    sts_build_pan_block(&pos.meter_id, false, &pan);
    sts_build_control_block(pos.kt, pos.sgc, pos.ti, pos.krn, &ctrl);
    sts_dkga_generate(pos.dkga, pos.vk1, pos.vk2, pan, ctrl,
                      meter.dkr.decoder_key);
    sts_tid_store_init(&meter.tid_store);

    sts_test_case_t tc;
    sts_conformance_roundtrip(&pos, &meter, 1,     STS_SUB_ELECTRICITY, 100, &tc);
    add_case(report, tc.name, tc.passed, tc.detail);
    sts_conformance_roundtrip(&pos, &meter, 100,   STS_SUB_ELECTRICITY, 200, &tc);
    add_case(report, tc.name, tc.passed, tc.detail);
    sts_conformance_roundtrip(&pos, &meter, 16383, STS_SUB_WATER,       300, &tc);
    add_case(report, tc.name, tc.passed, tc.detail);

    sts_conformance_roundtrip(&pos, &meter, 50, STS_SUB_ELECTRICITY, 100, &tc);
    add_case(report, "roundtrip_replay_rejected", !tc.passed, "重复 TID 应被拒");

    return STS_OK;
}

void sts_conformance_print(const sts_conformance_report_t* report)
{
    if (!report) return;
    printf("----- 一致性测试报告 -----\n");
    for (size_t i = 0; i < report->count; ++i) {
        const sts_test_case_t* c = &report->cases[i];
        printf("[%s] %-40s %s\n",
               c->passed ? "PASS" : "FAIL", c->name, c->detail);
    }
    printf("共 %zu 项，通过 %zu，失败 %zu\n",
           report->count, report->passed, report->failed);
}

/* ==========================================================================
 * 15. CLI
 * ========================================================================== */
static void fill_demo_pos(sts_pos_ctx_t* pos)
{
    memset(pos, 0, sizeof(*pos));
    pos->meter_id.iin_len = 4;
    strcpy(pos->meter_id.iin, "0000");
    pos->meter_id.mfr_code_len = 4;
    strcpy(pos->meter_id.mfr_code, "1234");
    strcpy(pos->meter_id.dsn, "00000001");
    pos->sgc  = 100702;
    pos->ti   = 1;
    pos->krn  = 1;
    pos->kt   = 2;
    pos->ken  = 255;
    pos->dkga = STS_DKGA02;
    pos->ea   = 9;
    pos->tct  = 2;
    memset(pos->vk1, 0x11, 8);
    memset(pos->vk2, 0x22, 8);
}

static void fill_demo_meter(sts_meter_ctx_t* meter, const sts_pos_ctx_t* pos)
{
    memset(meter, 0, sizeof(*meter));
    meter->meter_id = pos->meter_id;
    meter->ea  = pos->ea;
    meter->tct = pos->tct;
    meter->dkr.ti  = pos->ti;
    meter->dkr.krn = pos->krn;
    meter->dkr.kt  = pos->kt;
    meter->dkr.ken = pos->ken;
    u64 pan, ctrl;
    sts_build_pan_block(&pos->meter_id, false, &pan);
    sts_build_control_block(pos->kt, pos->sgc, pos->ti, pos->krn, &ctrl);
    sts_dkga_generate(pos->dkga, pos->vk1, pos->vk2, pan, ctrl,
                      meter->dkr.decoder_key);
    sts_tid_store_init(&meter->tid_store);
}

static void print_token_hex(const bits66_t* t)
{
    printf("TokenData(66bit): hi2=0x%X  lo64=0x%016llX\n",
           (unsigned)(t->hi2 & 0x3u),
           (unsigned long long)t->lo64);
}

static int cmd_gen(int argc, char** argv)
{
    if (argc < 3) { printf("用法: sts_toolkit gen <value> [tid]\n"); return 1; }
    u32 value = (u32)strtoul(argv[2], NULL, 10);
    u32 tid   = (argc >= 4) ? (u32)strtoul(argv[3], NULL, 10) : 100u;

    sts_pos_ctx_t pos; fill_demo_pos(&pos);
    sts_apdu_t apdu;
    sts_status_t s = sts_pos_make_transfer_credit(&pos, value,
                                                  STS_SUB_ELECTRICITY,
                                                  tid, &apdu);
    if (s != STS_OK) { printf("生成失败: %s\n", sts_status_str(s)); return 2; }

    printf("=== TransferCredit 令牌生成 ===\n");
    printf("MeterPAN : %s\n", apdu.meter_pan);
    printf("SGC      : %u\n", apdu.sgc);
    printf("TI/KRN/KT: %u/%u/%u\n", apdu.ti, apdu.krn, apdu.kt);
    printf("EA       : %u (%s)\n", apdu.ea, apdu.ea == 7 ? "STA" : "DEA");
    printf("TID      : %u\n", tid);
    printf("Amount   : %u\n", value);
    print_token_hex(&apdu.token);
    return 0;
}

static int cmd_parse(int argc, char** argv)
{
    if (argc < 4) { printf("用法: sts_toolkit parse <hi2_hex> <lo64_hex>\n"); return 1; }
    u32 hi2  = (u32)strtoul(argv[2], NULL, 16) & 0x3u;
    u64 lo64 = strtoull(argv[3], NULL, 16);

    bits66_t tok; tok.hi2 = (u8)hi2; tok.lo64 = lo64;

    sts_pos_ctx_t pos; fill_demo_pos(&pos);
    sts_meter_ctx_t meter; fill_demo_meter(&meter, &pos);

    sts_meter_parse_result_t res;
    sts_status_t s = sts_meter_parse(&meter, &tok, &res);
    if (s != STS_OK) { printf("解析失败: %s\n", sts_status_str(s)); return 2; }

    printf("=== 令牌解析结果 ===\n");
    printf("结果      : %s\n", res.result == STS_TOKEN_ACCEPT ? "ACCEPT" : "REJECT");
    if (res.is_class1) {
        printf("Class     : 1 (非仪表特定管理)\n");
        printf("SubClass  : %u\n", res.class1.subclass);
        printf("Control   : 0x%08X\n", res.class1.control);
        printf("MfrCode   : 0x%04X\n", res.class1.mfr_code);
    } else {
        printf("Class     : %u\n", res.decoded.token_class);
        printf("SubClass  : %u\n", res.decoded.subclass);
        printf("RND       : %u\n", res.decoded.rnd);
        printf("TID       : %u\n", res.decoded.tid);
        if (res.decoded.token_class == STS_CLASS_CREDIT)
            printf("Amount    : %u\n", sts_decode_transfer_amount(res.decoded.amount));
    }
    printf("认证      : %s (CRC err=%d)\n",
           res.auth.authentic ? "OK" : "FAIL", (int)res.auth.crc_error);
    printf("验证      : %s\n", res.valid.valid ? "OK" : "FAIL");
    return 0;
}

static int cmd_test(int argc, char** argv)
{
    (void)argc; (void)argv;
    sts_conformance_report_t rep;
    sts_status_t s = sts_conformance_run_all(&rep);
    if (s != STS_OK) { printf("测试套件执行失败: %s\n", sts_status_str(s)); return 2; }
    sts_conformance_print(&rep);
    return rep.failed ? 1 : 0;
}

static int cmd_roundtrip(int argc, char** argv)
{
    u32 value = (argc >= 3) ? (u32)strtoul(argv[2], NULL, 10) : 100u;
    u32 tid   = (argc >= 4) ? (u32)strtoul(argv[3], NULL, 10) : 100u;
    sts_pos_ctx_t pos; fill_demo_pos(&pos);
    sts_meter_ctx_t meter; fill_demo_meter(&meter, &pos);

    sts_test_case_t tc;
    sts_status_t s = sts_conformance_roundtrip(&pos, &meter, value,
                                               STS_SUB_ELECTRICITY,
                                               tid, &tc);
    if (s != STS_OK) { printf("往返测试失败: %s\n", sts_status_str(s)); return 2; }
    printf("=== 端到端往返 ===\n");
    printf("用例 : %s\n", tc.name);
    printf("结果 : %s\n", tc.passed ? "PASS" : "FAIL");
    printf("详情 : %s\n", tc.detail);
    return tc.passed ? 0 : 1;
}

static int cmd_tcdu_enc(int argc, char** argv)
{
    if (argc < 3) { printf("用法: sts_toolkit tcdu-enc <value> [tid]\n"); return 1; }
    u32 value = (u32)strtoul(argv[2], NULL, 10);
    u32 tid   = (argc >= 4) ? (u32)strtoul(argv[3], NULL, 10) : 100u;

    sts_pos_ctx_t pos; fill_demo_pos(&pos);
    sts_apdu_t apdu;
    if (sts_pos_make_transfer_credit(&pos, value, STS_SUB_ELECTRICITY,
                                     tid, &apdu) != STS_OK) {
        printf("生成 APDU 失败\n"); return 2;
    }
    sts_tcdu_digital_t t;
    if (sts_tcdu_digital_encode(&apdu, &t) != STS_OK) {
        printf("TCDU 编码失败\n"); return 2;
    }
    char s[21];
    sts_tcdu_digital_to_string(&t, s);
    printf("数字令牌（20 位）: %s\n", s);

    sts_apdu_t back;
    if (sts_tcdu_digital_decode(&t, &back) == STS_OK)
        printf("回读 EA=%u TCT=%u SGC=%u\n", back.ea, back.tct, back.sgc);
    return 0;
}

static int cmd_tcdu_dec(int argc, char** argv)
{
    if (argc < 3) { printf("用法: sts_toolkit tcdu-dec <20位数字>\n"); return 1; }
    sts_tcdu_digital_t t;
    if (sts_tcdu_digital_from_string(argv[2], &t) != STS_OK) {
        printf("输入不是 20 位数字\n"); return 1;
    }
    sts_apdu_t apdu;
    sts_status_t s = sts_tcdu_digital_decode(&t, &apdu);
    if (s != STS_OK) { printf("TCDU 解码失败: %s\n", sts_status_str(s)); return 2; }

    sts_pos_ctx_t pos; fill_demo_pos(&pos);
    sts_meter_ctx_t meter; fill_demo_meter(&meter, &pos);
    sts_meter_parse_result_t res;
    s = sts_meter_parse(&meter, &apdu.token, &res);
    if (s != STS_OK) { printf("Meter 解析失败: %s\n", sts_status_str(s)); return 3; }
    printf("解析结果: %s\n", res.result == STS_TOKEN_ACCEPT ? "ACCEPT" : "REJECT");
    if (!res.is_class1)
        printf("Class=%u SubClass=%u TID=%u Amount=%u\n",
               res.decoded.token_class, res.decoded.subclass,
               res.decoded.tid, sts_decode_transfer_amount(res.decoded.amount));
    return 0;
}

static int cmd_tables_init(int argc, char** argv)
{
    const char* dir = (argc >= 3) ? argv[2] : "tables";

    const u8 sub1[16] = {12,10,8,4,3,15,0,2,14,1,5,13,6,9,7,11};
    const u8 sub2[16] = {6,9,7,4,3,10,12,14,2,13,1,15,0,11,8,5};
    const u8 perm_enc[64] = {
        29,27,34,9,16,62,55,2,40,49,38,25,33,61,30,23,
        1,41,21,57,42,15,5,58,19,53,22,17,48,28,24,39
    };
    const u8 perm_dec[64] = {
        44,16,7,32,51,22,49,52,63,3,42,36,39,56,35,21,
        4,27,57,15,24,62,18,26,30,11,43,1,29,0,14,40

    };

    char path[512];
    FILE* f;

    snprintf(path, sizeof(path), "%s/sub_table1.tbl", dir);
    f = fopen(path, "wb"); if (!f) { printf("无法写入 %s\n", path); return 1; }
    fwrite(sub1, 1, 16, f); fclose(f);
    printf("写入 %s\n", path);

    snprintf(path, sizeof(path), "%s/sub_table2.tbl", dir);
    f = fopen(path, "wb"); if (!f) { printf("无法写入 %s\n", path); return 1; }
    fwrite(sub2, 1, 16, f); fclose(f);
    printf("写入 %s\n", path);

    snprintf(path, sizeof(path), "%s/perm_table_enc.tbl", dir);
    f = fopen(path, "wb"); if (!f) { printf("无法写入 %s\n", path); return 1; }
    fwrite(perm_enc, 1, 64, f); fclose(f);
    printf("写入 %s\n", path);

    snprintf(path, sizeof(path), "%s/perm_table_dec.tbl", dir);
    f = fopen(path, "wb"); if (!f) { printf("无法写入 %s\n", path); return 1; }
    fwrite(perm_dec, 1, 64, f); fclose(f);
    printf("写入 %s\n", path);

    printf("注意：以上为示例值，仅用于自洽验证；真实设备请替换为 STSA 授权表。\n");
    return 0;
}

static int cmd_sta_selftest(int argc, char** argv)
{
    const char* dir = (argc >= 3) ? argv[2] : "tables";

    char s1[512], s2[512], pe[512], pd[512];
    snprintf(s1, sizeof(s1), "%s/sub_table1.tbl", dir);
    snprintf(s2, sizeof(s2), "%s/sub_table2.tbl", dir);
    snprintf(pe, sizeof(pe), "%s/perm_table_enc.tbl", dir);
    snprintf(pd, sizeof(pd), "%s/perm_table_dec.tbl", dir);

    sts_sta_tables_t enc_tbl, dec_tbl;
    memset(&enc_tbl, 0, sizeof(enc_tbl));
    memset(&dec_tbl, 0, sizeof(dec_tbl));

    if (sts_sta_load_tables(s1, s2, pe, &enc_tbl) != STS_OK) {
        printf("加载加密表失败\n"); return 2;
    }
    if (sts_sta_load_tables(s2, s1, pd, &dec_tbl) != STS_OK) {
        printf("加载解密表失败\n"); return 2;
    }

    u8 dk[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    u64 pt = 0xDEADBEEFCAFEBABEull;
    u64 ct = 0, rt = 0;
    if (sts_sta_encrypt(&enc_tbl, dk, pt, &ct) != STS_OK) {
        printf("STA 加密失败\n"); return 3;
    }
    if (sts_sta_decrypt(&dec_tbl, dk, ct, &rt) != STS_OK) {
        printf("STA 解密失败\n"); return 4;
    }
    printf("明文    : 0x%016llX\n", (unsigned long long)pt);
    printf("密文    : 0x%016llX\n", (unsigned long long)ct);
    printf("解密结果: 0x%016llX\n", (unsigned long long)rt);
    printf("STA 自检: %s\n", (rt == pt) ? "PASS" : "FAIL（示例表非互逆，属正常）");
    return (rt == pt) ? 0 : 1;
}

static void usage(void)
{
    printf("BS IEC 62055-41:2014 STS Toolkit (单文件版 v0.1)\n");
    printf("用法: sts_toolkit <command> [args]\n");
    printf("命令:\n");
    printf("  gen <value> [tid]        生成 TransferCredit 令牌\n");
    printf("  parse <hi2_hex> <lo64_hex>  解析 66 位令牌\n");
    printf("  roundtrip [value] [tid]  端到端 POS<->Meter 测试\n");
    printf("  test                     运行内置一致性测试套件\n");
    printf("  tcdu-enc <value> [tid]   生成 20 位数字令牌\n");
    printf("  tcdu-dec <20digits>      解析 20 位数字令牌\n");
    printf("  tables-init [dir]        生成 STA 表占位文件（默认 tables/）\n");
    printf("  sta-selftest [dir]       STA 表加解密自检\n");
    printf("  help                     显示帮助\n");
}

int sts_cli_main(int argc, char** argv)
{
    if (argc < 2) { usage(); return 0; }
    const char* cmd = argv[1];
    if (strcmp(cmd, "gen")          == 0) return cmd_gen(argc, argv);
    if (strcmp(cmd, "parse")        == 0) return cmd_parse(argc, argv);
    if (strcmp(cmd, "roundtrip")    == 0) return cmd_roundtrip(argc, argv);
    if (strcmp(cmd, "test")         == 0) return cmd_test(argc, argv);
    if (strcmp(cmd, "tcdu-enc")     == 0) return cmd_tcdu_enc(argc, argv);
    if (strcmp(cmd, "tcdu-dec")     == 0) return cmd_tcdu_dec(argc, argv);
    if (strcmp(cmd, "tables-init")  == 0) return cmd_tables_init(argc, argv);
    if (strcmp(cmd, "sta-selftest") == 0) return cmd_sta_selftest(argc, argv);
    if (strcmp(cmd, "help")         == 0) { usage(); return 0; }
    printf("未知命令: %s\n", cmd);
    usage();
    return 1;
}

/* ==========================================================================
 * 16. main
 * ========================================================================== */
int main(int argc, char** argv)
{
    return sts_cli_main(argc, argv);
}
