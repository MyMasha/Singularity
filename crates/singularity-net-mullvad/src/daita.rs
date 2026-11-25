//! DAITA — Defense Against Advanced Traffic Analysis (Maybenot v2 Constant-Size Packet Padding).
//!
//! Eliminates packet-size side-channels by framing and padding every WireGuard payload
//! to a uniform constant MTU block size (default `1360` bytes) and emitting indistinguishable
//! dummy cover frames during burst transitions.

use thiserror::Error;

pub const DAITA_MAGIC_DATA_FRAME: u8 = 0xD1;
pub const DAITA_MAGIC_COVER_DUMMY: u8 = 0xD0;
pub const DAITA_MAX_FRAME_SIZE: usize = u16::MAX as usize;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DaitaError {
    #[error("DAITA target frame size {requested_size} exceeds u16 maximum {max_size}")]
    FrameSizeExceedsU16 {
        requested_size: usize,
        max_size: usize,
    },
    #[error("Payload length {payload_len} exceeds DAITA constant frame capacity {max_capacity}")]
    PayloadExceedsBlockSize {
        payload_len: usize,
        max_capacity: usize,
    },
    #[error("Malformed DAITA frame header")]
    MalformedFrame,
}

/// Pads an arbitrary application/IP packet to a fixed `target_block_size` (e.g. 1360 bytes)
/// so an adversary observing encrypted WireGuard UDP packets sees identical constant-size datagrams.
/// Strictly validates that the frame size and payload length fit within `u16` (`<= 65535`) with
/// zero silent truncation.
pub fn pad_daita_frame(payload: &[u8], target_block_size: usize) -> Result<Vec<u8>, DaitaError> {
    if target_block_size > DAITA_MAX_FRAME_SIZE {
        return Err(DaitaError::FrameSizeExceedsU16 {
            requested_size: target_block_size,
            max_size: DAITA_MAX_FRAME_SIZE,
        });
    }
    let block_size = target_block_size.max(64);
    let max_capacity = block_size - 3; // 1 byte type + 2 bytes big-endian length
    if payload.len() > max_capacity {
        return Err(DaitaError::PayloadExceedsBlockSize {
            payload_len: payload.len(),
            max_capacity,
        });
    }

    let payload_len_u16 = u16::try_from(payload.len()).map_err(|_| {
        DaitaError::PayloadExceedsBlockSize {
            payload_len: payload.len(),
            max_capacity,
        }
    })?;

    let mut frame = vec![0u8; block_size];
    frame[0] = DAITA_MAGIC_DATA_FRAME;
    let len_be = payload_len_u16.to_be_bytes();
    frame[1] = len_be[0];
    frame[2] = len_be[1];
    frame[3..3 + payload.len()].copy_from_slice(payload);

    // Deterministic non-zero padding fill so plaintext entropy before AEAD encryption is uniform
    for (idx, b) in frame[3 + payload.len()..].iter_mut().enumerate() {
        *b = ((idx as u8).wrapping_mul(73)).wrapping_add(0x5A);
    }

    Ok(frame)
}

/// Synthesizes a constant-size DAITA Maybenot dummy cover packet indistinguishable after AEAD encryption.
pub fn synthesize_daita_cover_packet(target_block_size: usize) -> Vec<u8> {
    let block_size = target_block_size.clamp(64, DAITA_MAX_FRAME_SIZE);
    let mut frame = vec![0u8; block_size];
    frame[0] = DAITA_MAGIC_COVER_DUMMY;
    frame[1] = 0;
    frame[2] = 0;
    for (idx, b) in frame[3..].iter_mut().enumerate() {
        *b = ((idx as u8).wrapping_mul(37)).wrapping_add(0xA5);
    }
    frame
}

/// Unpads a decrypted DAITA frame. Returns `Ok(None)` if the frame was a Maybenot cover dummy packet.
pub fn unpad_daita_frame(frame: &[u8]) -> Result<Option<Vec<u8>>, DaitaError> {
    if frame.len() < 3 {
        return Err(DaitaError::MalformedFrame);
    }
    match frame[0] {
        DAITA_MAGIC_COVER_DUMMY => Ok(None),
        DAITA_MAGIC_DATA_FRAME => {
            let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
            if 3 + len > frame.len() {
                return Err(DaitaError::MalformedFrame);
            }
            Ok(Some(frame[3..3 + len].to_vec()))
        }
        _ => Err(DaitaError::MalformedFrame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_daita_frame_rejects_oversized_u16_frame_without_truncation() {
        let big_payload = vec![0xABu8; 65_536];
        assert_eq!(
            pad_daita_frame(&big_payload, 70_000),
            Err(DaitaError::FrameSizeExceedsU16 {
                requested_size: 70_000,
                max_size: u16::MAX as usize,
            })
        );
        assert_eq!(
            pad_daita_frame(b"tiny", 65_536),
            Err(DaitaError::FrameSizeExceedsU16 {
                requested_size: 65_536,
                max_size: u16::MAX as usize,
            })
        );

        // Max valid u16 frame (65535 bytes total -> 65532 bytes max payload) round-trips cleanly
        let max_valid_payload = vec![0x5Cu8; 65_532];
        let padded = pad_daita_frame(&max_valid_payload, 65_535).expect("max valid frame");
        assert_eq!(padded.len(), 65_535);
        let unpadded = unpad_daita_frame(&padded)
            .expect("unpad")
            .expect("data frame");
        assert_eq!(unpadded, max_valid_payload);

        // 65533 bytes into 65535 block exceeds capacity (65535 - 3 = 65532)
        let too_long = vec![0x5Cu8; 65_533];
        assert!(matches!(
            pad_daita_frame(&too_long, 65_535),
            Err(DaitaError::PayloadExceedsBlockSize { .. })
        ));
    }
}
