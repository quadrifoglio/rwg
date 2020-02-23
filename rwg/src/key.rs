//! WireGuard key management.

use std::fmt;

use libwg_sys as sys;

/// The size in bytes of a WireGuard key.
pub const KEY_SIZE: usize = 32;

/// A cryptographic key, public or private.
#[derive(Debug, Clone, PartialEq)]
pub struct Key {
    bytes: [u8; KEY_SIZE],
}

impl Key {
    /// Generate a new private key.
    pub fn generate_private() -> Key {
        let mut bytes = [0u8; KEY_SIZE];

        unsafe {
            sys::wg_generate_private_key(bytes.as_mut_ptr());
        }

        Key { bytes: bytes }
    }

    /// Construct a new key that is only composed of zero bytes.
    pub fn zero() -> Key {
        Key {
            bytes: [0u8; KEY_SIZE],
        }
    }

    /// Construct a key using the specified byte array.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Key {
        Key { bytes: bytes }
    }

    /// Construct a key using the specified byte slice.
    pub fn from_slice<B: AsRef<[u8]>>(slice: B) -> Result<Key, InvalidKey> {
        let mut bytes = [0u8; KEY_SIZE];
        let slice = slice.as_ref();

        if slice.len() != KEY_SIZE {
            return Err(InvalidKey::InvalidLength);
        }

        bytes.copy_from_slice(slice);

        Ok(Key { bytes: bytes })
    }

    /// Construct a key from the provided Base64-encoded bytes.
    pub fn from_base64(b64: &str) -> Result<Key, InvalidKey> {
        let mut bytes = [0u8; KEY_SIZE];
        let vec = base64::decode(b64).map_err(|_| InvalidKey::InvalidBase64)?;

        if vec.len() != KEY_SIZE {
            return Err(InvalidKey::InvalidLength);
        }

        bytes.copy_from_slice(&vec);

        Ok(Key { bytes: bytes })
    }

    /// Derive a public key from this key. Assumes `Self` is a private key.
    pub fn derive_public(&self) -> Key {
        let mut bytes = [0u8; KEY_SIZE];

        unsafe {
            sys::wg_generate_public_key(bytes.as_mut_ptr(), self.bytes.as_ptr() as *mut u8);
        }

        Key { bytes: bytes }
    }

    /// Get the Base64 representation of the key.
    pub fn to_base64(&self) -> String {
        base64::encode(&self.bytes)
    }

    /// Get a reference to the underlying key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

/// Errors that can happen when dealing with keys.
#[derive(Debug)]
pub enum InvalidKey {
    InvalidLength,
    InvalidBase64,
}

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InvalidKey::InvalidLength => write!(f, "key length must be {}", KEY_SIZE),
            InvalidKey::InvalidBase64 => write!(f, "invalid base64 string"),
        }
    }
}
