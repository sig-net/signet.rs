use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::bitcoin::encoding::{
    encode::Encodable,
    io::{BufRead, Error, Write},
    Decodable,
};

/// A Bitcoin script stored as raw bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ScriptBuf(pub Vec<u8>);

impl ScriptBuf {
    /// Creates a [`ScriptBuf`] from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let v = Vec::from_hex(s)?;
        Ok(Self::from_bytes(v))
    }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate.
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the BIP-143 P2WPKH script code for the 20-byte public key hash
    /// held in `self`: `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`
    /// (`76a914{hash}88ac`). This is the `script_code` argument expected by
    /// [`build_for_signing_segwit`](crate::bitcoin::BitcoinTransaction::build_for_signing_segwit)
    /// when signing a P2WPKH input.
    pub fn p2wpkh_script_code(&self) -> Self {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&self.0);
        script.extend_from_slice(&[0x88, 0xac]);
        Self(script)
    }
}

pub trait FromHex: Sized {
    /// Error type returned while parsing hex string.
    type Error: Sized + fmt::Debug + fmt::Display;

    /// Produces an object from a hex string.
    fn from_hex(s: &str) -> Result<Self, Self::Error>;
}

impl FromHex for Vec<u8> {
    type Error = String;

    fn from_hex(s: &str) -> Result<Self, Self::Error> {
        hex::decode(s).map_err(|e| e.to_string())
    }
}

impl Encodable for ScriptBuf {
    fn encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, Error> {
        self.0.encode(w)
    }
}

impl Decodable for ScriptBuf {
    fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self(Decodable::decode_from_finite_reader(r)?))
    }
}

impl serde::Serialize for ScriptBuf {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ScriptBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        if deserializer.is_human_readable() {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = ScriptBuf;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script hex")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if v.is_empty() {
                        Ok(ScriptBuf(vec![]))
                    } else {
                        ScriptBuf::from_hex(v).map_err(E::custom)
                    }
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut vec = Vec::new();
                    while let Some(byte) = seq.next_element()? {
                        vec.push(byte);
                    }
                    Ok(ScriptBuf(vec))
                }
            }
            deserializer.deserialize_any(Visitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = ScriptBuf;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script Vec<u8>")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(ScriptBuf::from_bytes(v.to_vec()))
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(ScriptBuf::from_bytes(v))
                }
            }
            deserializer.deserialize_byte_buf(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScriptBuf;

    #[test]
    fn test_p2wpkh_script_code_matches_rust_bitcoin() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::{PubkeyHash, ScriptBuf as RbScriptBuf};

        // 20-byte HASH160 of a compressed public key.
        let pubkey_hash: [u8; 20] = [
            0xcb, 0x8a, 0x30, 0x18, 0xcf, 0x27, 0x93, 0x11, 0xb1, 0x48, 0xcb, 0x8d, 0x13, 0x72,
            0x8b, 0xd8, 0xcb, 0xe9, 0x5b, 0xda,
        ];

        let our_script_code = ScriptBuf(pubkey_hash.to_vec()).p2wpkh_script_code();

        // BIP-143 P2WPKH scriptCode is the P2PKH script for the same key hash.
        let rb_script_code = RbScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(pubkey_hash));

        assert_eq!(our_script_code.0.as_slice(), rb_script_code.as_bytes());
    }
}
