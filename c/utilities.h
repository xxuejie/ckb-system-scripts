#ifndef CKB_SYSTEM_CONTRACT_UTILITIES_H_
#define CKB_SYSTEM_CONTRACT_UTILITIES_H_

#include <errno.h>
#include <limits.h>
#include "protocol_reader.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(Ckb_Protocol, x)

#define BLAKE2B_BLOCK_SIZE 32

#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -1
#define ERROR_WRONG_HEX_ENCODING -2
#define ERROR_SECP_ABORT -3
#define ERROR_LOAD_TX -4
#define ERROR_PARSE_TX -5
#define ERROR_SECP_INITIALIZE -6
#define ERROR_SECP_PARSE_PUBKEY -7
#define ERROR_SECP_PARSE_SIGNATURE -8
#define ERROR_PARSE_SIGHASH_TYPE -9
#define ERROR_LOAD_SELF_OUT_POINT -10
#define ERROR_PARSE_SELF_OUT_POINT -11
#define ERROR_LOAD_SELF_LOCK_HASH -12
#define ERROR_LOAD_LOCK_HASH -13
#define ERROR_INVALID_SIGHASH_TYPE -14
#define ERROR_SECP_VERIFICATION -15
#define ERROR_PARSE_SINGLE_INDEX -16
#define ERROR_SINGLE_INDEX_IS_INVALID -17
#define ERROR_PUBKEY_BLAKE160_HASH -18
#define ERROR_PUBKEY_BLAKE160_HASH_LENGTH -18
#define ERROR_LOAD_HEADER -19
#define ERROR_PARSE_HEADER -20
#define ERROR_DEPOSIT_HEADER -21
#define ERROR_LOAD_SINCE -22
#define ERROR_INVALID_SINCE -23
#define ERROR_EXTRACT_AR -24
#define ERROR_LOAD_CAPACITY -25
#define ERROR_OVERFLOW -26
#define ERROR_INVALID_OUTPUT_CAPACITY -27
#define ERROR_LOAD_SCRIPT -28
#define ERROR_PARSE_SCRIPT -29
#define ERROR_CODE_HASH_NOT_FOUND -30
#define ERROR_INVALID_DAO_VERSION -31

int char_to_int(char ch)
{
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  return ERROR_WRONG_HEX_ENCODING;
}

int hex_to_bin(char* buf, size_t buf_len, const char* hex)
{
  int i = 0;

  for (; i < buf_len && hex[i * 2] != '\0' && hex[i * 2 + 1] != '\0'; i++) {
    int a = char_to_int(hex[i * 2]);
    int b = char_to_int(hex[i * 2 + 1]);

    if (a < 0 || b < 0) {
      return ERROR_WRONG_HEX_ENCODING;
    }

    buf[i] = ((a & 0xF) << 4) | (b & 0xF);
  }

  if (i == buf_len && hex[i * 2] != '\0') {
    return ERROR_WRONG_HEX_ENCODING;
  }
  return i;
}

int secure_atoi(const char* s, int* result)
{
  char *end = NULL;
  errno = 0;
  long temp = strtol(s, &end, 10);
  if (end != s && errno != ERANGE && temp >= INT_MIN && temp <= INT_MAX) {
    *result = (int) temp;
    return 1;
  }
  return 0;
}

void extract_h256(ns(H256_struct_t) h256, uint8_t buf[32])
{
  buf[0] = ns(H256_u0(h256));
  buf[1] = ns(H256_u1(h256));
  buf[2] = ns(H256_u2(h256));
  buf[3] = ns(H256_u3(h256));
  buf[4] = ns(H256_u4(h256));
  buf[5] = ns(H256_u5(h256));
  buf[6] = ns(H256_u6(h256));
  buf[7] = ns(H256_u7(h256));
  buf[8] = ns(H256_u8(h256));
  buf[9] = ns(H256_u9(h256));
  buf[10] = ns(H256_u10(h256));
  buf[11] = ns(H256_u11(h256));
  buf[12] = ns(H256_u12(h256));
  buf[13] = ns(H256_u13(h256));
  buf[14] = ns(H256_u14(h256));
  buf[15] = ns(H256_u15(h256));
  buf[16] = ns(H256_u16(h256));
  buf[17] = ns(H256_u17(h256));
  buf[18] = ns(H256_u18(h256));
  buf[19] = ns(H256_u19(h256));
  buf[20] = ns(H256_u20(h256));
  buf[21] = ns(H256_u21(h256));
  buf[22] = ns(H256_u22(h256));
  buf[23] = ns(H256_u23(h256));
  buf[24] = ns(H256_u24(h256));
  buf[25] = ns(H256_u25(h256));
  buf[26] = ns(H256_u26(h256));
  buf[27] = ns(H256_u27(h256));
  buf[28] = ns(H256_u28(h256));
  buf[29] = ns(H256_u29(h256));
  buf[30] = ns(H256_u30(h256));
  buf[31] = ns(H256_u31(h256));
}

#define CHECK_LEN(x) if ((x) <= 0) { return x; }
#define TX_BUFFER_SIZE 1024 * 1024

#endif  /* CKB_SYSTEM_CONTRACT_UTILITIES_H_ */
