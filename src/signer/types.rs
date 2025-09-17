use serde::{Deserialize, Serialize};
use alloc::string::String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableAffinePoint {
    pub affine_point: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableScalar {
    pub scalar: String,
}

#[derive(Debug, Serialize)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}
