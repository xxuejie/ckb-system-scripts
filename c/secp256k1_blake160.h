#ifndef CKB_SYSTEM_CONTRACT_SECP256K1_BLAKE160_H_
#define CKB_SYSTEM_CONTRACT_SECP256K1_BLAKE160_H_

#include <stdio.h>
#include <stdlib.h>
#include "ckb_syscalls.h"
#include "blake2b.h"
#include "utilities.h"

#define SIGHASH_ALL 0x1
#define SIGHASH_NONE 0x2
#define SIGHASH_SINGLE 0x3
#define SIGHASH_MULTIPLE 0x4
#define SIGHASH_ANYONECANPAY 0x80

#define BLAKE160_SIZE 20

#define CUSTOM_ABORT 1
#define CUSTOM_PRINT_ERR 1

void custom_abort()
{
  syscall(SYS_exit, ERROR_SECP_ABORT, 0, 0, 0, 0, 0);
}

int custom_print_err(const char * arg, ...)
{
  (void) arg;
  return 0;
}

#include <secp256k1_static.h>
/*
 * We are including secp256k1 implementation directly so gcc can strip
 * unused functions. For some unknown reasons, if we link in libsecp256k1.a
 * directly, the final binary will include all functions rather than those used.
 */
#include <secp256k1.c>

#define TEMP_BUFFER_SIZE 256

void update_h256(blake2b_state *ctx, ns(H256_struct_t) h256)
{
  uint8_t buf[32];

  if (!h256) {
    return;
  }

  extract_h256(h256, buf);
  blake2b_update(ctx, buf, 32);
}

void update_uint32_t(blake2b_state *ctx, uint32_t v)
{
  char buf[32];
  snprintf(buf, 32, "%d", v);
  blake2b_update(ctx, buf, strlen(buf));
}

void update_uint64_t(blake2b_state *ctx, uint64_t v)
{
  char buf[32];
  snprintf(buf, 32, "%ld", v);
  blake2b_update(ctx, buf, strlen(buf));
}

void update_out_point(blake2b_state *ctx, ns(OutPoint_table_t) outpoint)
{
  update_h256(ctx, ns(OutPoint_tx_hash(outpoint)));
  update_uint32_t(ctx, ns(OutPoint_index(outpoint)));
}

int verify_sighash_all(const char* serialized_pubkey_hash,
                       const char* serialized_pubkey,
                       const char* serialized_signature)
{
  unsigned char hash[BLAKE2B_BLOCK_SIZE];
  char tx_buf[TX_BUFFER_SIZE];
  char buf[TEMP_BUFFER_SIZE];
  int ret, len;

  /* Check pubkey hash */
  len = hex_to_bin(buf, TEMP_BUFFER_SIZE, serialized_pubkey);
  CHECK_LEN(len);
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, buf, len);
  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  /* tx_buf is not yet used, we can borrow it as a temp buffer */
  if (hex_to_bin(tx_buf, BLAKE160_SIZE, serialized_pubkey_hash) != BLAKE160_SIZE) {
    return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
  }
  if (memcmp(tx_buf, hash, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  secp256k1_context context;
  if (secp256k1_context_initialize(&context, SECP256K1_CONTEXT_VERIFY) == 0) {
    return ERROR_SECP_INITIALIZE;
  }

  secp256k1_pubkey pubkey;
  ret = secp256k1_ec_pubkey_parse(&context, &pubkey, buf, len);
  if (ret == 0) {
    return ERROR_SECP_PARSE_PUBKEY;
  }

  ret = hex_to_bin(buf, TEMP_BUFFER_SIZE, serialized_signature);
  CHECK_LEN(ret);
  secp256k1_ecdsa_signature signature;
  ret = secp256k1_ecdsa_signature_parse_der(&context, &signature, buf, ret);
  if (ret == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  volatile uint64_t tx_size = TX_BUFFER_SIZE;
  if (ckb_load_tx(tx_buf, &tx_size, 0) != CKB_SUCCESS) {
    return ERROR_LOAD_TX;
  }

  /*
   * NOTE: we could've saved this tx structure somewhere, or pass it
   * in as a parameter to allow sharing of the data, but consider the
   * fact that signature is passed via witness, we can add a syscall
   * to expose transaction hash and sign the whole thing together instead
   * of signing each individual field here. Hence we are sticking with
   * the simple route here, and only load the whole transaction within
   * this function.
   */
  ns(Transaction_table_t) tx;
  if (!(tx = ns(Transaction_as_root(tx_buf)))) {
    return ERROR_PARSE_TX;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);

  /* Hash all inputs */
  ns(CellInput_vec_t) inputs = ns(Transaction_inputs(tx));
  size_t inputs_len = ns(CellInput_vec_len(inputs));
  for (int i = 0; i < inputs_len; i++) {
    ns(CellInput_table_t) input = ns(CellInput_vec_at(inputs, i));
    update_h256(&blake2b_ctx, ns(CellInput_tx_hash(input)));
    update_uint32_t(&blake2b_ctx, ns(CellInput_index(input)));
  }

  /* Hash all outputs */
  ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
  size_t outputs_len = ns(CellOutput_vec_len(outputs));
  for (int i = 0; i < outputs_len; i++) {
    ns(CellOutput_table_t) output = ns(CellOutput_vec_at(outputs, i));
    update_uint64_t(&blake2b_ctx, ns(CellOutput_capacity(output)));
    volatile uint64_t len = TEMP_BUFFER_SIZE;
    if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH) != CKB_SUCCESS) {
      return ERROR_LOAD_LOCK_HASH;
    }
    blake2b_update(&blake2b_ctx, buf, len);
    len = TEMP_BUFFER_SIZE;
    if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH) == CKB_SUCCESS) {
      blake2b_update(&blake2b_ctx, buf, len);
    }
  }

  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  ret = secp256k1_ecdsa_verify(&context, &signature, hash, &pubkey);
  if (ret != 1) {
    return ERROR_SECP_VERIFICATION;
  }
  return 0;
}

/*
 * Arguments are listed in the following order:
 * 0. program name
 * 1. pubkey blake160 hash, blake2b hash of pubkey first 20 bytes, used to shield the real
 * pubkey in lock script.
 * 2. type, SIGHASH type
 * 3. output(s), this is only used for SIGHASH_SINGLE and SIGHASH_MULTIPLE types,
 * for SIGHASH_SINGLE, it stores an integer denoting the index of output to be
 * signed; for SIGHASH_MULTIPLE, it stores a string of `,` separated array denoting
 * outputs to sign
 * 
 * Witness:
 * 4. pubkey, real pubkey used to identify token owner
 * 5. signature, signature used to present ownership
 */
int verify_bitcoin_sighash(int argc, char* argv[])
{
  unsigned char hash[BLAKE2B_BLOCK_SIZE];
  char tx_buf[TX_BUFFER_SIZE];
  char buf[TEMP_BUFFER_SIZE];
  int ret, len;

  if (argc != 5 && argc != 6) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  /* Check pubkey hash */
  len = hex_to_bin(buf, TEMP_BUFFER_SIZE, argv[argc - 2]);
  CHECK_LEN(len);
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, buf, len);
  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  /* tx_buf is not yet used, we can borrow it as a temp buffer */
  if (hex_to_bin(tx_buf, BLAKE160_SIZE, argv[1]) != BLAKE160_SIZE) {
    return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
  }
  if (memcmp(tx_buf, hash, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  secp256k1_context context;
  if (secp256k1_context_initialize(&context, SECP256K1_CONTEXT_VERIFY) == 0) {
    return ERROR_SECP_INITIALIZE;
  }

  secp256k1_pubkey pubkey;
  ret = secp256k1_ec_pubkey_parse(&context, &pubkey, buf, len);
  if (ret == 0) {
    return ERROR_SECP_PARSE_PUBKEY;
  }

  ret = hex_to_bin(buf, TEMP_BUFFER_SIZE, argv[argc - 1]);
  CHECK_LEN(ret);
  secp256k1_ecdsa_signature signature;
  ret = secp256k1_ecdsa_signature_parse_der(&context, &signature, buf, ret);
  if (ret == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, argv[2], strlen(argv[2]));
  int sighash_type;
  if (!secure_atoi(argv[2], &sighash_type)) {
    return ERROR_PARSE_SIGHASH_TYPE;
  }

  volatile uint64_t tx_size = TX_BUFFER_SIZE;
  if (ckb_load_tx(tx_buf, &tx_size, 0) != CKB_SUCCESS) {
    return ERROR_LOAD_TX;
  }

  ns(Transaction_table_t) tx;
  if (!(tx = ns(Transaction_as_root(tx_buf)))) {
    return ERROR_PARSE_TX;
  }

  if ((sighash_type & SIGHASH_ANYONECANPAY) != 0) {
    /* Only hash current input */
    volatile uint64_t len = TEMP_BUFFER_SIZE;
    if (ckb_load_input_by_field(buf, &len, 0, 0, CKB_SOURCE_CURRENT, CKB_INPUT_FIELD_OUT_POINT) != CKB_SUCCESS) {
      return ERROR_LOAD_SELF_OUT_POINT;
    }
    ns(OutPoint_table_t) op;
    if (!(op = ns(OutPoint_as_root(buf)))) {
      return ERROR_PARSE_SELF_OUT_POINT;
    }
    update_out_point(&blake2b_ctx, op);
  } else {
    /* Hash all inputs */
    ns(CellInput_vec_t) inputs = ns(Transaction_inputs(tx));
    size_t inputs_len = ns(CellInput_vec_len(inputs));
    for (int i = 0; i < inputs_len; i++) {
      ns(CellInput_table_t) input = ns(CellInput_vec_at(inputs, i));
      update_h256(&blake2b_ctx, ns(CellInput_tx_hash(input)));
      update_uint32_t(&blake2b_ctx, ns(CellInput_index(input)));
    }
  }

  switch (sighash_type & (~SIGHASH_ANYONECANPAY)) {
    case SIGHASH_ALL:
      {
        ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
        size_t outputs_len = ns(CellOutput_vec_len(outputs));
        for (int i = 0; i < outputs_len; i++) {
          ns(CellOutput_table_t) output = ns(CellOutput_vec_at(outputs, i));
          update_uint64_t(&blake2b_ctx, ns(CellOutput_capacity(output)));
          volatile uint64_t len = TEMP_BUFFER_SIZE;
          if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH) != CKB_SUCCESS) {
            return ERROR_LOAD_LOCK_HASH;
          }
          blake2b_update(&blake2b_ctx, buf, len);
          len = TEMP_BUFFER_SIZE;
          if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH) == CKB_SUCCESS) {
            blake2b_update(&blake2b_ctx, buf, len);
          }
        }
      }
      break;
    case SIGHASH_SINGLE:
      {
        if (argc != 5) {
          return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
        }
        ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
        size_t outputs_len = ns(CellOutput_vec_len(outputs));
        int i = -1;
        if (!secure_atoi(argv[3], &i)) {
          return ERROR_PARSE_SINGLE_INDEX;
        }
        if (i < 0 || i >= outputs_len) {
          return ERROR_SINGLE_INDEX_IS_INVALID;
        }
        ns(CellOutput_table_t) output = ns(CellOutput_vec_at(outputs, i));
        update_uint64_t(&blake2b_ctx, ns(CellOutput_capacity(output)));
        volatile uint64_t len = TEMP_BUFFER_SIZE;
        if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH) != CKB_SUCCESS) {
          return ERROR_LOAD_LOCK_HASH;
        }
        blake2b_update(&blake2b_ctx, buf, len);
        len = TEMP_BUFFER_SIZE;
        if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH) == CKB_SUCCESS) {
          blake2b_update(&blake2b_ctx, buf, len);
        }
      }
      break;
    case SIGHASH_MULTIPLE:
      {
        /* Leverages strtol to implement split */
        if (argc != 5) {
          return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
        }
        ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
        size_t outputs_len = ns(CellOutput_vec_len(outputs));
        const char* ptr = argv[3];
        size_t len = strlen(ptr);
        while (ptr - argv[3] < len) {
          char* end = NULL;
          int i = (int) strtol(ptr, &end, 10);
          if (end != ptr) {
            if (i < 0 || i >= outputs_len) {
              return ERROR_SINGLE_INDEX_IS_INVALID;
            }
            ns(CellOutput_table_t) output = ns(CellOutput_vec_at(outputs, i));
            update_uint64_t(&blake2b_ctx, ns(CellOutput_capacity(output)));
            volatile uint64_t len = TEMP_BUFFER_SIZE;
            if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH) != CKB_SUCCESS) {
              return ERROR_LOAD_LOCK_HASH;
            }
            blake2b_update(&blake2b_ctx, buf, len);
            len = TEMP_BUFFER_SIZE;
            if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH) == CKB_SUCCESS) {
              blake2b_update(&blake2b_ctx, buf, len);
            }
          }
          if (*end == '\0') {
            break;
          }
          ptr = end + 1;
        }
      }
      break;
    case SIGHASH_NONE:
      break;
    default:
      return ERROR_INVALID_SIGHASH_TYPE;
  }

  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  ret = secp256k1_ecdsa_verify(&context, &signature, hash, &pubkey);
  if (ret != 1) {
    return ERROR_SECP_VERIFICATION;
  }
  return 0;
}

#endif  /* CKB_SYSTEM_CONTRACT_SECP256K1_BLAKE160_H_ */
