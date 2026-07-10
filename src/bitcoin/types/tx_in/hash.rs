use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::bitcoin::encoding::{
    encode::Encodable,
    extensions::WriteExt,
    io::{BufRead, Error},
    Decodable,
};

/// A 32-byte double-SHA256 hash stored in internal byte order (reversed from display).
#[derive(
    Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn as_byte_array(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        // A hex txid string is in display order (big-endian); store it in
        // internal (little-endian) order so it serializes correctly on the wire.
        let bytes = hex::decode(hex)?;
        let mut arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        arr.reverse();
        Ok(Self(arr))
    }
}

impl Hash {
    pub const fn all_zeros() -> Self {
        Self([0; 32])
    }
}

impl Encodable for Hash {
    fn encode<W: WriteExt + ?Sized>(&self, w: &mut W) -> Result<usize, Error> {
        // `self.0` is already in internal (little-endian) wire order.
        w.emit_slice(&self.0).map(|_| self.0.len())
    }
}

impl Decodable for Hash {
    fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut buf: [u8; 32] = [0; 32];
        r.read_exact(&mut buf)?; // 32 bytes in internal (little-endian) wire order
        Ok(Self(buf))
    }
}

impl FromStr for Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

use hex::encode;

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reversed: Vec<u8> = self.0.iter().rev().cloned().collect();
        write!(f, "{}", encode(reversed))
    }
}

#[cfg(test)]
mod tests {
    use super::Hash;

    #[test]
    fn test_from_hex_wrong_length_errors() {
        // 2 bytes, not 32: must return Err, not panic in try_into().expect().
        assert!(Hash::from_hex("0102").is_err());
    }

    #[test]
    fn test_from_hex_too_long_errors() {
        // 33 bytes: also a length error, not a panic.
        assert!(Hash::from_hex(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff11"
        )
        .is_err());
    }

    #[test]
    fn test_from_hex_valid_length_ok() {
        assert!(
            Hash::from_hex("bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a")
                .is_ok()
        );
    }

    #[test]
    fn test_from_hex_display_round_trips() {
        // A txid hex string is in display order; parsing it and displaying it
        // again must yield the same string (rust-bitcoin's convention).
        let display = "bc25cc0dddd0a202c21e66521a692c0586330a9a9dcc38ccd9b4d2093037f31a";
        let hash = Hash::from_hex(display).unwrap();
        assert_eq!(hash.to_string(), display);
    }
}
