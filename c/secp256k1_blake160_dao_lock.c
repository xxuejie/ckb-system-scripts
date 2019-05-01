#include "secp256k1_blake160.h"
#include "ckb_syscalls.h"

#define DAO_VERSION 0x1

#define LOCK_PERIOD_BLOCKS 2000
#define MATURITY_BLOCKS 100

#define HEADER_BUFFER_SIZE 2048

int extract_header_data(size_t index, size_t source, uint64_t* block_number, uint64_t* ar)
{
  char buf[HEADER_BUFFER_SIZE];
  volatile uint64_t buf_size = HEADER_BUFFER_SIZE;
  ns(Header_table_t) header;
  ns(Bytes_table_t) bytes;
  flatbuffers_uint8_vec_t seq;

  if (ckb_load_header(buf, &buf_size, 0, index, source) != CKB_SUCCESS) {
    return ERROR_LOAD_HEADER;
  }
  if (!(header = ns(Header_as_root(buf)))) {
    return ERROR_PARSE_HEADER;
  }
  bytes = ns(Header_dao(header));
  seq = ns(Bytes_seq(bytes));
  if (flatbuffers_uint8_vec_at(seq, 0) != DAO_VERSION) {
    return ERROR_INVALID_DAO_VERSION;
  }

  *ar = ((uint64_t) flatbuffers_uint8_vec_at(seq, 1)) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 2)) >> 8) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 3)) >> 16) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 4)) >> 24) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 5)) >> 32) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 6)) >> 40) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 7)) >> 48) |
        (((uint64_t) flatbuffers_uint8_vec_at(seq, 8)) >> 56);
  *block_number = ns(Header_number(header));
  return 0;
}

int extract_output_total_capacities(uint64_t* capacities)
{
  char buf[TX_BUFFER_SIZE];
  volatile uint64_t buf_size = TX_BUFFER_SIZE;
  ns(Transaction_table_t) tx;

  if (ckb_load_tx(buf, &buf_size, 0) != CKB_SUCCESS) {
    return ERROR_LOAD_TX;
  }
  if (!(tx = ns(Transaction_as_root(buf)))) {
    return ERROR_PARSE_TX;
  }

  *capacities = 0;
  ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
  size_t outputs_len = ns(CellOutput_vec_len(outputs));
  for (int i = 0; i < outputs_len; i++) {
    ns(CellOutput_table_t) output = ns(CellOutput_vec_at(outputs, i));
    *capacities += ns(CellOutput_capacity(output));
  }
  return 0;
}

int verify_dao()
{
  uint64_t deposit_block_number = 0, deposit_ar = 1;
  uint64_t withdraw_block_number = 0, withdraw_ar = 1;
  uint64_t output_total_capacities = 0;
  int ret;

  ret = extract_header_data(0, CKB_SOURCE_CURRENT, &deposit_block_number, &deposit_ar);
  if (ret != 0) {
    return ret;
  }
  /*
   * For simplicity, this lock script assumes the first dep in current TX
   * contains the block header treated as withdraw block.
   */
  ret = extract_header_data(0, CKB_SOURCE_DEP, &withdraw_block_number, &withdraw_ar);
  if (ret != 0) {
    return ret;
  }
  ret = extract_output_total_capacities(&output_total_capacities);
  if (ret != 0) {
    return ret;
  }

  /* windowleft = l - ((h_w - h_d)) % l */
  uint64_t windowleft = LOCK_PERIOD_BLOCKS - (withdraw_block_number - deposit_block_number) % LOCK_PERIOD_BLOCKS;
  /* since > min(maturity, windowleft) */
  uint64_t minimal_since = withdraw_block_number + ((windowleft > MATURITY_BLOCKS) ? MATURITY_BLOCKS : windowleft) + 1;

  volatile uint64_t specified_since = 0;
  volatile uint64_t specified_since_length = 8;
  /* RISC-V uses little endian */
  if (ckb_load_input_by_field(((void *) (&specified_since)),
                              &specified_since_length,
                              0,
                              0,
                              CKB_SOURCE_CURRENT,
                              CKB_INPUT_FIELD_SINCE) != CKB_SUCCESS) {
    return ERROR_LOAD_SINCE;
  }
  if (specified_since < minimal_since) {
    return ERROR_INVALID_SINCE;
  }

  volatile uint64_t input_capacity = 0;
  volatile uint64_t input_capacity_length = 8;
  /* RISC-V uses little endian */
  if (ckb_load_cell_by_field(((void *) (&input_capacity)),
                             &input_capacity_length,
                             0,
                             0,
                             CKB_SOURCE_CURRENT,
                             CKB_CELL_FIELD_CAPACITY) != CKB_SUCCESS) {
    return ERROR_LOAD_CAPACITY;
  }

  __int128 maximum_output_capacity = ((__int128) input_capacity) * ((__int128) withdraw_ar) / ((__int128) deposit_ar);
  if (((__int128) ((uint64_t) maximum_output_capacity)) != maximum_output_capacity) {
    return ERROR_OVERFLOW;
  }

  if (output_total_capacities > ((uint64_t) maximum_output_capacity)) {
    return ERROR_INVALID_OUTPUT_CAPACITY;
  }

  return 0;
}


int main(int argc, char* argv[])
{
  int ret;

  if (argc != 4) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  ret = verify_sighash_all(argv[1], argv[2], argv[3]);
  if (ret != 0) {
    return ret;
  }

  return verify_dao();
}
