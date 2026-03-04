use std::convert::TryInto;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A network packet used by the smart‑fuzz engine.
///
/// The format is intentionally simple to keep parsing lightweight while still
/// demonstrating how fuzzed payloads can be inspected and generated.
///
/// ```text
///  +-------------------+-----------------+--------------------+
///  | protocol_version  | packet_type     | payload_length      |
///  +-------------------+-----------------+--------------------+
///  | 1 byte            | 2 bytes         | 4 bytes             |
///  +-------------------+-----------------+--------------------+
///  | <payload>                                 (variable)   │
///  +-------------------------------------------------------+
/// ```
///
/// The `protocol_version` field is currently fixed to `0x01`.  
/// The packet type can be any u16 value; the engine uses it only for
/// classification. The payload length must match the actual number of bytes
/// that follow.
///
/// Author: Myroslav Mokhammad Abdeljawwad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Protocol version (currently 1).
    pub protocol_version: u8,
    /// Arbitrary packet type identifier.
    pub packet_type: u16,
    /// Length of the payload in bytes.
    pub payload_length: u32,
    /// Payload data. May contain any binary data.
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum PacketError {
    /// The input buffer is too short to contain a complete header.
    IncompleteHeader,
    /// The reported payload length does not match the actual remaining bytes.
    LengthMismatch { expected: usize, found: usize },
    /// General I/O error during serialization/deserialization.
    Io(std::io::Error),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::IncompleteHeader => write!(f, "buffer too short to contain packet header"),
            PacketError::LengthMismatch { expected, found } => write!(
                f,
                "payload length mismatch: expected {} bytes but got {}",
                expected, found
            ),
            PacketError::Io(err) => write!(f, "I/O error while processing packet: {}", err),
        }
    }
}

impl std::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PacketError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PacketError {
    fn from(err: std::io::Error) -> Self {
        PacketError::Io(err)
    }
}

impl Packet {
    /// Serializes the packet into a byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut buf = Vec::with_capacity(7 + self.payload.len());
        buf.push(self.protocol_version);
        buf.extend_from_slice(&self.packet_type.to_be_bytes());
        buf.extend_from_slice(&(self.payload_length as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Parses a packet from the given byte slice.
    ///
    /// Returns an error if the data is malformed or incomplete.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PacketError> {
        const HEADER_LEN: usize = 7; // 1 + 2 + 4

        if data.len() < HEADER_LEN {
            return Err(PacketError::IncompleteHeader);
        }

        let protocol_version = data[0];
        let packet_type = u16::from_be_bytes(data[1..3].try_into().unwrap());
        let payload_length =
            u32::from_be_bytes(data[3..7].try_into().unwrap()) as usize;

        if data.len() - HEADER_LEN != payload_length {
            return Err(PacketError::LengthMismatch {
                expected: payload_length,
                found: data.len() - HEADER_LEN,
            });
        }

        let payload = data[HEADER_LEN..].to_vec();

        Ok(Self {
            protocol_version,
            packet_type,
            payload_length: payload_length as u32,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_serialization() {
        let original = Packet {
            protocol_version: 1,
            packet_type: 0x1234,
            payload_length: 5,
            payload: vec![10, 20, 30, 40, 50],
        };

        let bytes = original.to_bytes().expect("serialization should succeed");
        assert_eq!(bytes.len(), 12);
        let parsed = Packet::from_bytes(&bytes).expect("parsing should succeed");

        assert_eq!(parsed.protocol_version, original.protocol_version);
        assert_eq!(parsed.packet_type, original.packet_type);
        assert_eq!(parsed.payload_length, original.payload_length);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn incomplete_header_error() {
        let data = vec![0x01, 0x12]; // too short
        match Packet::from_bytes(&data) {
            Err(PacketError::IncompleteHeader) => {}
            _ => panic!("expected IncompleteHeader error"),
        }
    }

    #[test]
    fn length_mismatch_error() {
        let data = vec![0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x05, 10, 20]; // declared 5 but only 2 bytes
        match Packet::from_bytes(&data) {
            Err(PacketError::LengthMismatch { expected: 5, found }) => assert_eq!(found, 2),
            _ => panic!("expected LengthMismatch error"),
        }
    }
}