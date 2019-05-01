#include "ckb_syscalls.h"
#include "utilities.h"

int extract_input_count(size_t *count)
{
  char tx_buf[TX_BUFFER_SIZE];
  ns(Transaction_table_t) tx;
  if (!(tx = ns(Transaction_as_root(tx_buf)))) {
    return ERROR_PARSE_TX;
  }

  ns(CellInput_vec_t) inputs = ns(Transaction_inputs(tx));
  *count = ns(CellInput_vec_len(inputs));
  return 0;
}

#define SCRIPT_BUFFER_SIZE 1024

/*
 * Given one argument containing the hex representation of a hash,
 * this lock script ensures at least one of the input script uses
 * the same code hash as the specified hash here. This script is
 * typically used to simplify the transaction where multiple input
 * scripts share the same unlock logic. Instead of doing the same
 * verification multiple times, we can use this script to only do
 * the verification once, hence saving cycle costs.
 */
int main(int argc, char* argv[])
{
  char script_buffer[SCRIPT_BUFFER_SIZE];
  unsigned char target_hash[BLAKE2B_BLOCK_SIZE], hash[BLAKE2B_BLOCK_SIZE];
  int ret, len;
  size_t input_count;

  if (argc != 2) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  len = hex_to_bin(target_hash, BLAKE2B_BLOCK_SIZE, argv[1]);
  CHECK_LEN(len);

  ret = extract_input_count(&input_count);
  if (ret != 0) {
    return ret;
  }

  for (size_t i = 0; i < input_count; i++) {
    volatile uint64_t script_buffer_length = SCRIPT_BUFFER_SIZE;
    if (ckb_load_cell_by_field(script_buffer, &script_buffer_length, 0,
                               i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK) != CKB_SUCCESS) {
      return ERROR_LOAD_SCRIPT;
    }
    ns(Script_table_t) script;
    if (!(script = ns(Script_as_root(script_buffer)))) {
      return ERROR_PARSE_SCRIPT;
    }
    extract_h256(ns(Script_code_hash(script)), hash);
    if (memcmp(target_hash, hash, BLAKE2B_BLOCK_SIZE) == 0) {
      return 0;
    }
  }
  return ERROR_CODE_HASH_NOT_FOUND;
}
