#![recursion_limit = "256"]
//! FlyPoW is a deterministic research implementation of a FlyHash-inspired
//! proof-of-work function.
//!
//! This crate is not a production cryptocurrency implementation. In
//! particular, it does not include networking, persistent chain state,
//! transaction signatures, or a peer-to-peer consensus protocol.

pub mod block;
pub mod compact_index;
pub mod dataset;
pub mod economics;
pub mod flyhash;
pub mod hash;
pub mod network;
pub mod pow;
pub mod site;
pub mod useful;
pub mod web;
pub mod target_authority;
pub mod product_identity;

pub use block::{BlockTemplate, MinedHeader};
pub use dataset::{CanonicalDataset, CanonicalSynapse, DatasetError};
pub use flyhash::{FlyHashOutput, FlyHashParams, FlyHashProfile};
pub use hash::{Hash256, decode_hash, encode_hex};
pub use pow::{
    DatasetFlyPowContext, DatasetMiningOutcome, FlyPowContext, MiningOutcome, PowError,
    leading_zero_bits, meets_difficulty,
};
pub use useful::{NeuronFingerprint, UsefulIndex, UsefulIndexError};

pub mod explorer_types;
pub mod explorer_projection;
pub mod explorer;

pub mod evidence_manifest;
