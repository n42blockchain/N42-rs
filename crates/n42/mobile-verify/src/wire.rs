//! Wire format header for N42 mobile protocol messages.
//!
//! All messages (StreamPacket, CacheSyncMessage, VerificationReceipt)
//! share a common 4-byte header:
//!
//! ```text
//! ┌──────────┬──────────┬────────┐
//! │ magic 2B │ version  │ flags  │
//! │ 0x4E 0x32│  1B      │  1B    │
//! │  "N2"    │  0x01    │  0x00  │
//! └──────────┴──────────┴────────┘
//! ```

/// Magic bytes: ASCII "N2" — quick identification of N42 mobile protocol.
pub const MAGIC: [u8; 2] = [0x4E, 0x32];

/// Current wire format version.
pub const VERSION_1: u8 = 0x01;

/// Total header size in bytes.
pub const HEADER_SIZE: usize = 4;

/// Flag: bytecodes section is present.
pub const FLAG_HAS_BYTECODES: u8 = 0x01;

/// Wire format errors.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Input too short to contain a valid header.
    #[error("data too short: need {HEADER_SIZE} bytes, got {0}")]
    TooShort(usize),

    /// Magic bytes do not match.
    #[error("invalid magic: expected 0x4E32, got 0x{0:02X}{1:02X}")]
    InvalidMagic(u8, u8),

    /// Version is not supported.
    #[error("unsupported version: {0} (max supported: {VERSION_1})")]
    UnsupportedVersion(u8),

    /// Unexpected end of data during decoding.
    #[error("unexpected end of data at offset {0}")]
    UnexpectedEof(usize),

    /// A length field exceeds remaining data.
    #[error("length overflow: need {need} bytes at offset {offset}, got {remaining}")]
    LengthOverflow {
        offset: usize,
        need: usize,
        remaining: usize,
    },

    /// An invalid tag value was encountered.
    #[error("invalid tag 0x{0:02X} at offset {1}")]
    InvalidTag(u8, usize),
}

/// Encodes a wire header into `buf`: `magic(2B) + version(1B) + flags(1B)`.
pub fn encode_header(buf: &mut Vec<u8>, version: u8, flags: u8) {
    buf.extend_from_slice(&MAGIC);
    buf.push(version);
    buf.push(flags);
}

/// Decoded wire header.
pub struct WireHeader {
    pub version: u8,
    pub flags: u8,
}

/// Decodes the wire header from `data`, returning the header and remaining payload.
pub fn decode_header(data: &[u8]) -> Result<(WireHeader, &[u8]), WireError> {
    if data.len() < HEADER_SIZE {
        return Err(WireError::TooShort(data.len()));
    }

    if data[0] != MAGIC[0] || data[1] != MAGIC[1] {
        return Err(WireError::InvalidMagic(data[0], data[1]));
    }

    let version = data[2];
    if version != VERSION_1 {
        return Err(WireError::UnsupportedVersion(version));
    }

    let flags = data[3];
    Ok((WireHeader { version, flags }, &data[HEADER_SIZE..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut buf = Vec::new();
        encode_header(&mut buf, VERSION_1, 0x00);
        assert_eq!(buf.len(), HEADER_SIZE);

        let (header, rest) = decode_header(&buf).unwrap();
        assert_eq!(header.version, VERSION_1);
        assert_eq!(header.flags, 0x00);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_encode_with_flags() {
        let mut buf = Vec::new();
        encode_header(&mut buf, VERSION_1, FLAG_HAS_BYTECODES);

        let (header, _) = decode_header(&buf).unwrap();
        assert_eq!(header.flags, FLAG_HAS_BYTECODES);
    }

    #[test]
    fn test_decode_with_payload() {
        let mut buf = Vec::new();
        encode_header(&mut buf, VERSION_1, 0x00);
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let (header, rest) = decode_header(&buf).unwrap();
        assert_eq!(header.version, VERSION_1);
        assert_eq!(rest, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_too_short() {
        let result = decode_header(&[0x4E]);
        assert!(matches!(result, Err(WireError::TooShort(1))));

        let result = decode_header(&[]);
        assert!(matches!(result, Err(WireError::TooShort(0))));
    }

    #[test]
    fn test_invalid_magic() {
        let result = decode_header(&[0xFF, 0xFF, 0x01, 0x00]);
        assert!(matches!(result, Err(WireError::InvalidMagic(0xFF, 0xFF))));
    }

    #[test]
    fn test_unsupported_version() {
        let data = [MAGIC[0], MAGIC[1], 0xFF, 0x00];
        let result = decode_header(&data);
        assert!(matches!(result, Err(WireError::UnsupportedVersion(0xFF))));
    }

    #[test]
    fn test_version_zero_rejected() {
        // version=0x00 is below VERSION_1; strict equality check must reject it.
        let data = [MAGIC[0], MAGIC[1], 0x00, 0x00];
        let result = decode_header(&data);
        assert!(matches!(result, Err(WireError::UnsupportedVersion(0x00))));
    }

    #[test]
    fn test_version_1_accepted() {
        let data = [MAGIC[0], MAGIC[1], VERSION_1, 0x00];
        let result = decode_header(&data);
        assert!(result.is_ok());
    }
}
