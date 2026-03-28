//! Serializable payloads used by external signing backends.
use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Response returned by a remote signer that includes the full ECDSA signature parts.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

/// Hex-encoded affine point (uncompressed) for the signature's R component.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableAffinePoint {
    pub affine_point: String,
}

/// Hex-encoded scalar for the signature's S component.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableScalar {
    pub scalar: String,
}

/// Request sent to a signing service describing what and where to sign.
#[derive(Debug, Serialize)]
pub struct SignRequest {
    /// The 32-byte hash to be signed (e.g., Keccak256 of an EVM tx or SHA256d of a BTC sighash).
    pub payload: [u8; 32],
    /// Derivation path identifying which key to use (e.g., `"m/44'/60'/0'/0/0"`).
    pub path: String,
    /// Version of the signing key to use.
    pub key_version: u32,
}
