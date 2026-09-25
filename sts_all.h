/* ============================================================================
 * sts_all.h — BS IEC 62055-41:2014 STS 工具包 单头文件版
 *
 * 用法：
 *   #include "sts_all.h"
 *
 * MSVC 编译：
 *   cl /W4 /std:c11 /D_CRT_SECURE_NO_WARNINGS sts_all.c /Fe:sts_toolkit.exe
 *
 * 功能：
 *   - POS 端令牌生成器（TransferCredit / TestDisplay / Class2 / 密钥更换对）
 *   - 电表端令牌解析器（认证、验证、接受/拒绝、密钥更换实际生效）
 *   - TCDU 数字令牌序列化（IEC 62055-51 数字载体）
 *   - 一致性测试工具（内置测试套件）
 *   - 命令行接口（gen / parse / roundtrip / test / tcdu-enc / tcdu-dec
 *                    tables-init / sta-selftest）
 *
 * ⚠️ 关于 EA=07 (STA)：
 *   替换表/排列表属于 STS 协会受控信息。本文件内置的示例表只能保证
 *   工具包内自洽，不能与真实 STS 设备互通。用于真实设备时，请把
 *   授权表值放入 tables/*.tbl，然后调用 sts_sta_load_tables() 加载。
 * ==========================================================================*/
#ifndef STS_ALL_H
#define STS_ALL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 基础类型                                                            */
/* ------------------------------------------------------------------ */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  i32;
typedef bool     boolean;

/* 66 位令牌：低 64 位 + 高 2 位 */
typedef struct {
    u64 lo64;   /* bit 0..63 */
    u8  hi2;    /* bit 64..65，仅低 2 位有效 */
} bits66_t;

/* 状态码 */
typedef enum {
    STS_OK = 0,
    STS_ERR_INVALID_ARG,
    STS_ERR_BUFFER_TOO_SMALL,
    STS_ERR_TABLE_NOT_LOADED,
    STS_ERR_CRC,
    STS_ERR_MFR_CODE,
    STS_ERR_TID_OLD,
    STS_ERR_TID_USED,
    STS_ERR_KEY_EXPIRED,
    STS_ERR_DDTK,
    STS_ERR_OVERFLOW,
    STS_ERR_KEY_TYPE,
    STS_ERR_FORMAT,
    STS_ERR_RANGE,
    STS_ERR_FUNCTION,
    STS_ERR_CRYPTO,
    STS_ERR_NOT_IMPLEMENTED
} sts_status_t;

/* ------------------------------------------------------------------ */
/* 常量与枚举                                                          */
/* ------------------------------------------------------------------ */
typedef enum {
    STS_BASE_1993 = 0,
    STS_BASE_2014 = 1,
    STS_BASE_2035 = 2
} sts_base_date_t;

typedef enum {
    STS_CLASS_CREDIT    = 0,
    STS_CLASS_NON_METER = 1,
    STS_CLASS_METER     = 2,
    STS_CLASS_RESERVED3 = 3
} sts_token_class_t;

typedef enum {
    STS_SUB_ELECTRICITY = 0,
    STS_SUB_WATER       = 1,
    STS_SUB_GAS         = 2,
    STS_SUB_TIME        = 3,
    STS_SUB_CURRENCY    = 4
} sts_credit_subclass_t;

typedef enum {
    STS_SUB2_SET_MPL          = 0,
    STS_SUB2_CLEAR_CREDIT     = 1,
    STS_SUB2_SET_TARIFF       = 2,
    STS_SUB2_SET_1ST_DEC_KEY  = 3,
    STS_SUB2_SET_2ND_DEC_KEY  = 4,
    STS_SUB2_CLEAR_TAMPER     = 5,
    STS_SUB2_SET_MPPUL        = 6,
    STS_SUB2_SET_WM_FACTOR    = 7
} sts_meter_subclass_t;

typedef enum {
    STS_DKGA01 = 1,
    STS_DKGA02 = 2,
    STS_DKGA03 = 3
} sts_dkga_code_t;

typedef enum {
    STS_TCT_HANDHELD        = 0,
    STS_TCT_MAGCARD         = 1,
    STS_TCT_DIGITAL         = 2,
    STS_TCT_PROPRIETARY_3_6 = 3,
    STS_TCT_VIRTUAL_07      = 7
} sts_tct_t;

typedef enum {
    STS_TOKEN_ACCEPT = 0,
    STS_TOKEN_1ST_KCT,
    STS_TOKEN_2ND_KCT,
    STS_TOKEN_OVERFLOW,
    STS_TOKEN_KEY_TYPE_ERROR,
    STS_TOKEN_FORMAT_ERROR,
    STS_TOKEN_RANGE_ERROR,
    STS_TOKEN_FUNCTION_ERROR
} sts_token_result_t;

/* ------------------------------------------------------------------ */
/* 状态码字符串                                                        */
/* ------------------------------------------------------------------ */
const char* sts_status_str(sts_status_t s);

/* ------------------------------------------------------------------ */
/* CRC-16                                                              */
/* ------------------------------------------------------------------ */
u16 sts_crc16(const u8* data, size_t len);
u16 sts_crc_for_token(const bits66_t* token);

/* ------------------------------------------------------------------ */
/* Luhn 校验位                                                         */
/* ------------------------------------------------------------------ */
u8   sts_luhn_check_digit(const char* digits, size_t len);
bool sts_luhn_verify(const char* digits, size_t len);

/* ------------------------------------------------------------------ */
/* MeterPAN / PANBlock / CONTROLBlock                                  */
/* ------------------------------------------------------------------ */
typedef struct {
    u8  iin_len;          /* 6 或 4 */
    char iin[7];
    u8  mfr_code_len;     /* 2 或 4 */
    char mfr_code[5];
    char dsn[9];
} sts_meter_id_t;

sts_status_t sts_build_drn(const sts_meter_id_t* id, char* out, size_t out_sz);
sts_status_t sts_drn_check_digit(const sts_meter_id_t* id, u8* out_digit);
sts_status_t sts_build_meter_pan(const sts_meter_id_t* id, char pan[19]);
sts_status_t sts_build_pan_block(const sts_meter_id_t* id, bool is_dctk,
                                 u64* out_pan_block);
sts_status_t sts_build_control_block(u8 kt, u32 sgc, u8 ti, u8 krn,
                                     u64* out_ctrl_block);

/* ------------------------------------------------------------------ */
/* TID                                                                 */
/* ------------------------------------------------------------------ */
bool         sts_is_leap_year(int year);
sts_status_t sts_calc_tid(sts_base_date_t base,
                          int year, int month, int day,
                          int hour, int minute, int second,
                          u32* out_tid);
bool         sts_is_reserved_tid(u32 tid);
u32          sts_next_tid_in_minute(u32 tid, u32 seq);

/* ------------------------------------------------------------------ */
/* 令牌结构                                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    u8   token_class;
    u8   subclass;
    u8   rnd;
    u32  tid;
    u16  amount;
    u16  mpl;
    u16  register_to_clear;
    u16  tariff_rate;
    u8   krn;
    u8   kt;
    u8   kenho;
    u32  nkho;
    u8   kenlo;
    u32  nklo;
    u16  mppul;
    u16  wm_factor;
    u8   ro;
    u16  crc;
} sts_token_decoded_t;

typedef struct {
    u8   token_class;
    u8   subclass;
    u32  control;
    u16  mfr_code;
    u16  crc;
} sts_token_class1_t;

u16          sts_encode_transfer_amount(u32 value);
u32          sts_decode_transfer_amount(u16 field);
sts_status_t sts_token_decode(const bits66_t* raw, sts_token_decoded_t* out);
sts_status_t sts_token_encode(const sts_token_decoded_t* in, bits66_t* out);

/* ------------------------------------------------------------------ */
/* 2 类位插入/提取                                                      */
/* ------------------------------------------------------------------ */
bits66_t sts_insert_class_bits(u64 data64, u8 class2);
u8       sts_extract_class_bits(bits66_t in, u64* out_data64);

/* ------------------------------------------------------------------ */
/* DES / TDEA（纯软件）                                                */
/* ------------------------------------------------------------------ */
sts_status_t sts_des_encrypt_block(const u8 key[8], const u8 in[8], u8 out[8]);
sts_status_t sts_des_decrypt_block(const u8 key[8], const u8 in[8], u8 out[8]);
sts_status_t sts_tdea_encrypt_block(const u8 k1[8], const u8 k2[8],
                                    const u8 in[8], u8 out[8]);
sts_status_t sts_tdea_decrypt_block(const u8 k1[8], const u8 k2[8],
                                    const u8 in[8], u8 out[8]);
void         sts_des_set_odd_parity(u8 key[8]);

/* ------------------------------------------------------------------ */
/* DKGA                                                                */
/* ------------------------------------------------------------------ */
sts_status_t sts_dkga_generate(sts_dkga_code_t algo,
                               const u8 vk1[8], const u8 vk2[8],
                               u64 pan_block, u64 ctrl_block,
                               u8 out_decoder_key[8]);
bool         sts_dkga01_is_applicable(const char* drn, u32 sgc, u8 kt, u8 krn);

/* ------------------------------------------------------------------ */
/* STA                                                                 */
/* ------------------------------------------------------------------ */
typedef struct {
    u8   sub_table[2][16];
    u8   perm_table[64];
    bool loaded;
} sts_sta_tables_t;

sts_status_t sts_sta_load_tables(const char* sub_path1,
                                 const char* sub_path2,
                                 const char* perm_path,
                                 sts_sta_tables_t* out);
sts_status_t sts_sta_encrypt(const sts_sta_tables_t* tbl,
                             const u8 decoder_key[8],
                             u64 data_block, u64* out_cipher);
sts_status_t sts_sta_decrypt(const sts_sta_tables_t* tbl,
                             const u8 decoder_key[8],
                             u64 cipher_block, u64* out_data);

/* ------------------------------------------------------------------ */
/* APDU                                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    char meter_pan[19];
    u8   tct;
    u8   dkga;
    u8   ea;
    u32  sgc;
    u8   ti;
    u8   krn;
    u8   kt;
    u8   ken;
    bits66_t token;
} sts_apdu_t;

typedef struct {
    bool authentic;
    bool crc_error;
    bool mfr_code_error;
} sts_auth_result_t;

typedef struct {
    bool valid;
    bool old_error;
    bool used_error;
    bool key_expired_error;
    bool ddtk_error;
} sts_valid_result_t;

sts_status_t sts_apdu_serialize(const sts_apdu_t* apdu,
                                u8* buf, size_t buf_sz, size_t* out_len);
sts_status_t sts_apdu_deserialize(const u8* buf, size_t buf_len,
                                  sts_apdu_t* out_apdu);

/* ------------------------------------------------------------------ */
/* TCDU（IEC 62055-51 数字载体）                                       */
/* ------------------------------------------------------------------ */
#define STS_TCDU_DIGITS 20
typedef struct { u8 digits[STS_TCDU_DIGITS]; } sts_tcdu_digital_t;

sts_status_t sts_tcdu_digital_encode(const sts_apdu_t* apdu,
                                     sts_tcdu_digital_t* out);
sts_status_t sts_tcdu_digital_decode(const sts_tcdu_digital_t* in,
                                     sts_apdu_t* out_apdu);
void         sts_tcdu_digital_to_string(const sts_tcdu_digital_t* t,
                                        char out[STS_TCDU_DIGITS + 1]);
sts_status_t sts_tcdu_digital_from_string(const char* s,
                                          sts_tcdu_digital_t* out);

/* ------------------------------------------------------------------ */
/* POS 上下文                                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    sts_meter_id_t   meter_id;
    u32              sgc;
    u8               ti;
    u8               krn;
    u8               kt;
    u8               ken;
    sts_dkga_code_t  dkga;
    u8               ea;
    u8               tct;
    u8               vk1[8];
    u8               vk2[8];
    sts_sta_tables_t sta_tables;
} sts_pos_ctx_t;

sts_status_t sts_pos_init(sts_pos_ctx_t* ctx);
sts_status_t sts_pos_make_transfer_credit(sts_pos_ctx_t* ctx,
                                          u32 value,
                                          sts_credit_subclass_t subclass,
                                          u32 tid,
                                          sts_apdu_t* out_apdu);
sts_status_t sts_pos_make_test_display(sts_pos_ctx_t* ctx,
                                       u8 subclass, u32 control,
                                       u16 mfr_code, u32 tid,
                                       sts_apdu_t* out_apdu);
sts_status_t sts_pos_make_class2(sts_pos_ctx_t* ctx,
                                 u8 subclass, u32 tid,
                                 const sts_token_decoded_t* params,
                                 sts_apdu_t* out_apdu);
sts_status_t sts_pos_make_key_change_pair(sts_pos_ctx_t* ctx,
                                          const sts_meter_id_t* new_id,
                                          u32 new_sgc, u8 new_ti,
                                          u8 new_krn, u8 new_kt,
                                          u8 new_ken, u32 tid,
                                          sts_apdu_t* out_1st,
                                          sts_apdu_t* out_2nd);
sts_status_t sts_pos_apdu_to_token_data(const sts_apdu_t* apdu,
                                        bits66_t* out_token_data);

/* ------------------------------------------------------------------ */
/* Meter 上下文                                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    u8   decoder_key[8];
    u8   ti;
    u8   krn;
    u8   kt;
    u8   ken;
    bool ken_enabled;
} sts_dkr_t;

#define STS_TID_HISTORY 50
typedef struct {
    u32    tids[STS_TID_HISTORY];
    u32    oldest;
    size_t count;
    size_t head;
} sts_tid_store_t;

typedef struct {
    bool active;
    bool have_1st;
    bool have_2nd;
    u8   nkho[4];
    u8   nklo[4];
    u8   new_krn;
    u8   new_kt;
    u8   new_ti;
    u8   new_ken;
    u8   ro;
    u32  tid_1st;
    u32  tid_2nd;
    u64  first_seen_ms;
} sts_kct_staging_t;

typedef struct {
    sts_meter_id_t   meter_id;
    sts_dkr_t        dkr;
    sts_tid_store_t  tid_store;
    u8               ea;
    u8               tct;
    bool             key_expiry_enabled;
    sts_sta_tables_t sta_tables;
    sts_kct_staging_t kct_staging;
} sts_meter_ctx_t;

typedef struct {
    sts_auth_result_t   auth;
    sts_valid_result_t  valid;
    sts_token_result_t  result;
    sts_token_decoded_t decoded;
    sts_token_class1_t  class1;
    bool                is_class1;
} sts_meter_parse_result_t;

sts_status_t sts_meter_init(sts_meter_ctx_t* ctx);
sts_status_t sts_meter_parse(sts_meter_ctx_t* ctx,
                             const bits66_t* token_data,
                             sts_meter_parse_result_t* out);

void sts_tid_store_init(sts_tid_store_t* s);
bool sts_tid_store_contains(const sts_tid_store_t* s, u32 tid);
void sts_tid_store_insert(sts_tid_store_t* s, u32 tid);
void sts_tid_store_clear(sts_tid_store_t* s);

bool         sts_key_type_change_allowed(u8 parent_kt, u8 child_kt, u8 tct);
sts_status_t sts_meter_apply_kct(sts_meter_ctx_t* ctx,
                                 const sts_token_decoded_t* tok,
                                 u64 now_ms, bool* out_applied);

/* ------------------------------------------------------------------ */
/* 一致性测试                                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    char name[64];
    bool passed;
    char detail[256];
} sts_test_case_t;

typedef struct {
    sts_test_case_t cases[128];
    size_t count;
    size_t passed;
    size_t failed;
} sts_conformance_report_t;

sts_status_t sts_conformance_run_all(sts_conformance_report_t* report);
sts_status_t sts_conformance_roundtrip(sts_pos_ctx_t* pos,
                                       sts_meter_ctx_t* meter,
                                       u32 value,
                                       sts_credit_subclass_t subclass,
                                       u32 tid,
                                       sts_test_case_t* out_case);
void         sts_conformance_print(const sts_conformance_report_t* report);

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */
int sts_cli_main(int argc, char** argv);

#ifdef __cplusplus
}
#endif
#endif /* STS_ALL_H */