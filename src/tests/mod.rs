mod dao;
mod secp256k1_blake160_multisig_all;
mod secp256k1_blake160_sighash_all;

use ckb_crypto::secp::Privkey;
use ckb_mock_tx_types::{MockCellDep, MockInfo, MockInput, MockTransaction, ReprMockTransaction};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{cell::ResolvedTransaction, EpochExt, HeaderView, TransactionView},
    packed::{self, Byte32, CellOutput, OutPoint, WitnessArgs},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use std::collections::HashMap;

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

lazy_static! {
    pub static ref SIGHASH_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_blake160_sighash_all")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_data")[..]);
    pub static ref DAO_BIN: Bytes = Bytes::from(&include_bytes!("../../specs/cells/dao")[..]);
    pub static ref MULTISIG_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/secp256k1_blake160_multisig_all")[..]);
}

#[derive(Default, Clone)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub epoches: HashMap<Byte32, EpochExt>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl CellDataProvider for DummyDataLoader {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<Bytes> {
        self.cells.get(out_point).map(|(_, data)| data.clone())
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.cells
            .get(out_point)
            .map(|(_, data)| CellOutput::calc_data_hash(data))
    }
}

impl HeaderProvider for DummyDataLoader {
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }
}

pub fn blake160(message: &[u8]) -> Bytes {
    Bytes::from(ckb_hash::blake2b_256(message)[..20].to_vec())
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, key, 0, witnesses_len)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                let sig = key.sign_recoverable(&message).expect("sign");
                witness
                    .as_builder()
                    .lock(Some(Bytes::from(sig.serialize())).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn build_mock_transaction<DL: CellDataProvider + HeaderProvider>(
    rtx: &ResolvedTransaction,
    dl: &DL,
) -> Result<MockTransaction, String> {
    // For system script tests, dep group is never used. A more general
    // utility should process dep groups as well.
    assert!(rtx.resolved_dep_groups.is_empty());

    fn c<O, N>(old: &O) -> N
    where
        O: ckb_types::prelude::Entity,
        N: ckb_types_200::prelude::Entity,
    {
        N::from_slice(old.as_slice()).expect("parsing")
    }

    let mut inputs = Vec::with_capacity(rtx.resolved_inputs.len());
    for (i, input) in rtx.resolved_inputs.iter().enumerate() {
        inputs.push(MockInput {
            input: c(&rtx
                .transaction
                .inputs()
                .get(i)
                .ok_or_else(|| format!("Cannot locate cell input {} in transaction", i))?),
            output: c(&input.cell_output),
            data: input
                .mem_cell_data
                .clone()
                .or_else(|| dl.get_cell_data(&input.out_point))
                .unwrap(),
            header: input
                .transaction_info
                .clone()
                .map(|info| info.block_hash)
                .map(|h| c(&h)),
        });
    }
    let mut cell_deps = Vec::with_capacity(rtx.resolved_cell_deps.len());
    for (i, dep) in rtx.resolved_cell_deps.iter().enumerate() {
        cell_deps.push(MockCellDep {
            cell_dep: c(&rtx.transaction.cell_deps().get(i).ok_or_else(|| {
                format!(
                    "Cannot locate cell dep {}, maybe you are using a dep group?",
                    i
                )
            })?),
            output: c(&dep.cell_output),
            data: dep
                .mem_cell_data
                .clone()
                .or_else(|| dl.get_cell_data(&dep.out_point))
                .unwrap(),
            header: dep
                .transaction_info
                .clone()
                .map(|info| info.block_hash)
                .map(|h| c(&h)),
        });
    }
    let mut header_deps = Vec::with_capacity(rtx.transaction.header_deps().len());
    for header_hash in rtx.transaction.header_deps_iter() {
        let old_header = dl
            .get_header(&header_hash)
            .ok_or_else(|| format!("Cannot find header {:x}!", header_hash))?;
        let new_header: ckb_types_200::packed::Header = c(&old_header.data());

        use ckb_types_200::prelude::IntoHeaderView;
        header_deps.push(new_header.into_view());
    }
    Ok(MockTransaction {
        mock_info: MockInfo {
            inputs,
            cell_deps,
            header_deps,
            extensions: Vec::new(),
        },
        tx: c(&rtx.transaction.data()),
    })
}

pub fn save_tx<DL: CellDataProvider + HeaderProvider>(
    rtx: &ResolvedTransaction,
    dl: &DL,
    prefix: &str,
) {
    if let Some(path) = std::env::var_os("DUMP_TXS_PATH") {
        let mock_tx = build_mock_transaction(rtx, dl).expect("build mock tx");

        let tx_hash = mock_tx.tx.calc_tx_hash();
        let repr_tx: ReprMockTransaction = mock_tx.into();
        let tx_json = serde_json::to_string_pretty(&repr_tx).expect("to json");

        let directory = std::path::Path::new(&path).join(prefix);
        std::fs::create_dir_all(&directory).expect("mkdir -p");
        let full_path = directory.join(format!("0x{:x}.json", tx_hash));
        std::fs::write(full_path, tx_json).expect("write");
    }
}
