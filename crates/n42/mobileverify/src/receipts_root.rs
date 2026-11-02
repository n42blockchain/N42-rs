// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The native chain's receipts root (gov5 `internal.ReceiptsRootFor` with
//! `EthereumReceiptEncoding` false): `keccak256(concat_i RLP(receipt_i))`,
//! each receipt `[status, cumulativeGasUsed, [[address, [topics], data]...]]`
//! with no type byte and no bloom. No receipts hash to `keccak256("")`, not
//! the empty trie root.

use alloy_primitives::{B256, Log, keccak256};
use alloy_rlp::{BufMut, Encodable, Header};

/// RLP of one receipt in the native encoding (`Receipts.EncodeIndex`).
pub fn encode_native_receipt(success: bool, cumulative_gas_used: u64, logs: &[Log]) -> Vec<u8> {
    let status: u64 = u64::from(success);
    let mut logs_payload = Vec::new();
    for log in logs {
        encode_log(log, &mut logs_payload);
    }
    let mut payload = Vec::new();
    status.encode(&mut payload);
    cumulative_gas_used.encode(&mut payload);
    Header { list: true, payload_length: logs_payload.len() }.encode(&mut payload);
    payload.extend_from_slice(&logs_payload);
    let mut out = Vec::with_capacity(payload.len() + 4);
    Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

fn encode_log(log: &Log, out: &mut dyn BufMut) {
    let topics = log.data.topics();
    let topics_len: usize = topics.iter().map(Encodable::length).sum();
    let mut payload = Vec::new();
    log.address.encode(&mut payload);
    Header { list: true, payload_length: topics_len }.encode(&mut payload);
    for t in topics {
        t.encode(&mut payload);
    }
    log.data.data.encode(&mut payload);
    Header { list: true, payload_length: payload.len() }.encode(out);
    out.put_slice(&payload);
}

/// The root over already-encoded receipts.
pub fn native_receipts_root<T: AsRef<[u8]>>(encoded: &[T]) -> B256 {
    let mut buf = Vec::new();
    for e in encoded {
        buf.extend_from_slice(e.as_ref());
    }
    keccak256(&buf)
}
