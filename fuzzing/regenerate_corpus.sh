#!/usr/bin/env bash
set -ex

TRACER="${TRACER:-ckb-vm-syscall-tracer}"

# Inspired from https://stackoverflow.com/a/246128
FUZZING_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TOP=$FUZZING_DIR/..

cd $FUZZING_DIR
rm -rf dumps corpus

cd $TOP
# Even when some test fails, the corpus will still be useful
DUMP_TXS_PATH=fuzzing/dumps cargo test --no-fail-fast || true

cd $FUZZING_DIR
for f in $(find dumps -type f -name "0x*.json"); do
  target=${f/dumps/corpus}
  target=${target/json/data}

  rm -rf corpus/tmp
  mkdir -p corpus/tmp
  $TRACER -o corpus/tmp -t $f --script-group lock --cell-kind input --cell-index 0

  mkdir -p $(dirname $target)
  cp corpus/tmp/vm_0_0.traces $target

  rm -rf corpus/tmp
done

for f in $(find corpus -type f -name "0x*.data"); do
  target=${f/corpus/corpus_text}
  target=${target/data/txt}

  mkdir -p $(dirname $target)
  $FUZZING_DIR/binary_to_text_converter $f > $target
done
