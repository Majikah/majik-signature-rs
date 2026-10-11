//! Port of `anchor/types.ts` — chain-anchor types (chain-agnostic).

use serde::{Deserialize, Serialize};

pub type MajikChainAnchorMemo = String;
pub type MajikChainAnchorTxSignature = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MajikChainAnchorDigest {
    /// Always `"SHA3-512"`.
    pub algorithm: String,
    /// Hex-encoded, 128 chars — sourced as-is from `get_seal_info().seal_hash`.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MajikChainAnchorPayload {
    /// e.g. `"solana"` — a plain string so the crate stays chain-agnostic.
    pub chain: String,
    pub network: String,
    pub digest: MajikChainAnchorDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MajikChainAnchorStatus {
    Pending,
    Confirmed,
    Finalized,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikChainAnchor {
    /// Always `1`.
    pub version: u8,
    /// Internal UUID, matches `chain_anchors.id`.
    pub id: String,
    pub payload: MajikChainAnchorPayload,
    /// Exact string written on-chain: `"majik-notary-v-1:{sealHash}"`.
    pub memo: MajikChainAnchorMemo,
    /// base58.
    pub tx_signature: MajikChainAnchorTxSignature,
    /// `null` until confirmed.
    pub slot: Option<u64>,
    /// Unix seconds, `null` until confirmed.
    pub block_time: Option<u64>,
    /// ISO 8601, set when status first reaches `"confirmed"`.
    pub confirmed_at: Option<String>,
    pub status: MajikChainAnchorStatus,
}
