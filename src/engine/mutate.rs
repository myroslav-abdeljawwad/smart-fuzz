/// # smart-fuzz – Mutation Engine
///
/// This module implements the core mutation logic used by the AI‑guided fuzzing engine.
/// It provides a set of deterministic and stochastic mutation strategies that operate on
/// `Packet` instances defined in `src/protocol/packet.rs`. The module is intentionally
/// self‑contained so it can be unit tested independently from the rest of the engine.
///
/// Author: Myroslav Mokhammad Abdeljawwad
///
/// # Design notes
///
/// * Mutations are applied in-place to reduce allocation overhead.
/// * All mutation functions return a `Result<(), MutationError>` to allow callers to
///   distinguish between recoverable errors (e.g. invalid configuration) and fatal ones.
/// * The random number generator is seeded from the global `Config` to ensure reproducibility
///   when needed, but can also be driven by a user supplied seed.
///
/// # Usage example
///
/// ```rust
/// use smart_fuzz::engine::{mutate, Config};
/// use smart_fuzz::protocol::Packet;
///
/// let mut packet = Packet::from_bytes(&[0x01, 0x02, 0x03]).unwrap();
/// let cfg = Config::default();
/// mutate::apply_mutations(&mut packet, &cfg).expect("mutation failed");
/// ```

use rand::{rngs::StdRng, Rng, SeedableRng};
use std::convert::TryInto;

use crate::{
    config::Config,
    protocol::packet::Packet,
};

#[derive(Debug)]
pub enum MutationError {
    /// The packet buffer was empty and could not be mutated.
    EmptyBuffer,
    /// Configuration values were out of bounds.
    InvalidConfig(String),
    /// General I/O error during mutation (unlikely in this context).
    IoError(std::io::Error),
}

impl From<std::io::Error> for MutationError {
    fn from(err: std::io::Error) -> Self {
        MutationError::IoError(err)
    }
}

/// Number of random mutations to apply when `mutations_per_packet` is set.
const DEFAULT_MUTATIONS_PER_PACKET: usize = 5;

/// Maximum allowed payload size after mutation (prevents runaway growth).
const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64 KiB

/// Apply all configured mutation strategies to the given packet.
///
/// The function respects `Config::mutation_rate` and performs a random number of
/// mutations between 1 and `mutations_per_packet`. If `mutation_rate` is zero, no
/// mutations are performed.
pub fn apply_mutations(packet: &mut Packet, cfg: &Config) -> Result<(), MutationError> {
    if packet.is_empty() {
        return Err(MutationError::EmptyBuffer);
    }

    let mut rng = StdRng::seed_from_u64(cfg.random_seed);

    // Decide whether to mutate at all.
    if rng.gen_bool(cfg.mutation_rate as f64) {
        let num_mutations = rng.gen_range(1..=cfg.mutations_per_packet.unwrap_or(DEFAULT_MUTATIONS_PER_PACKET));
        for _ in 0..num_mutations {
            // Pick a random strategy based on configured weights.
            let strategy = pick_strategy(&mut rng, cfg);
            match strategy {
                MutationStrategy::BitFlip => flip_random_bits(packet, &mut rng)?,
                MutationStrategy::ByteInsert => insert_random_byte(packet, &mut rng)?,
                MutationStrategy::ByteDelete => delete_random_byte(packet, &mut rng)?,
                MutationStrategy::Substitute => substitute_random_bytes(packet, &mut rng, cfg.substitution_length)?,
            }
        }
    }

    // Enforce maximum size.
    if packet.len() > MAX_PAYLOAD_SIZE {
        packet.truncate(MAX_PAYLOAD_SIZE);
    }

    Ok(())
}

/// Enumerates the mutation strategies supported by this engine.
#[derive(Copy, Clone)]
enum MutationStrategy {
    BitFlip,
    ByteInsert,
    ByteDelete,
    Substitute,
}

fn pick_strategy(rng: &mut StdRng, cfg: &Config) -> MutationStrategy {
    // Weighted random selection based on config probabilities.
    let total = cfg.bit_flip_weight
        + cfg.byte_insert_weight
        + cfg.byte_delete_weight
        + cfg.substitute_weight;

    let choice = rng.gen_range(0..total);
    if choice < cfg.bit_flip_weight {
        MutationStrategy::BitFlip
    } else if choice < cfg.bit_flip_weight + cfg.byte_insert_weight {
        MutationStrategy::ByteInsert
    } else if choice < cfg.bit_flip_weight + cfg.byte_insert_weight + cfg.byte_delete_weight {
        MutationStrategy::ByteDelete
    } else {
        MutationStrategy::Substitute
    }
}

/// Flip a random number of bits in the packet payload.
///
/// The number of bits flipped is determined by `cfg.bits_to_flip`. If zero, one bit
/// will be flipped.
fn flip_random_bits(packet: &mut Packet, rng: &mut StdRng) -> Result<(), MutationError> {
    let len = packet.len();
    if len == 0 {
        return Err(MutationError::EmptyBuffer);
    }

    let bits_to_flip = std::cmp::max(1, rng.gen_range(1..=packet.config.bits_to_flip));
    for _ in 0..bits_to_flip {
        let byte_idx = rng.gen_range(0..len);
        let bit_mask = 1u8 << rng.gen_range(0..8);
        packet[byte_idx] ^= bit_mask;
    }
    Ok(())
}

/// Insert a random byte at a random position.
fn insert_random_byte(packet: &mut Packet, rng: &mut StdRng) -> Result<(), MutationError> {
    let len = packet.len();
    let pos = if len == 0 { 0 } else { rng.gen_range(0..=len) };
    let byte = rng.gen::<u8>();
    packet.insert(pos, byte);
    Ok(())
}

/// Delete a random byte from the packet.
fn delete_random_byte(packet: &mut Packet, rng: &mut StdRng) -> Result<(), MutationError> {
    if packet.is_empty() {
        return Err(MutationError::EmptyBuffer);
    }
    let pos = rng.gen_range(0..packet.len());
    packet.remove(pos);
    Ok(())
}

/// Replace a contiguous slice with random bytes.
///
/// The length of the slice is controlled by `sub_len`. If the packet is shorter,
/// the whole payload will be replaced.
fn substitute_random_bytes(
    packet: &mut Packet,
    rng: &mut StdRng,
    sub_len: usize,
) -> Result<(), MutationError> {
    if packet.is_empty() {
        return Err(MutationError::EmptyBuffer);
    }

    let len = packet.len();
    let replace_len = std::cmp::min(sub_len, len);
    let start = rng.gen_range(0..=len - replace_len);

    for i in 0..replace_len {
        packet[start + i] = rng.gen::<u8>();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::protocol::packet::Packet;

    fn make_packet() -> Packet {
        Packet::from_bytes(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap()
    }

    #[test]
    fn test_bit_flip_mutation_changes_payload() {
        let mut pkt = make_packet();
        let cfg = Config::default();

        // Force bit flip strategy
        let mut rng = StdRng::seed_from_u64(42);
        flip_random_bits(&mut pkt, &mut rng).unwrap();

        assert_ne!(pkt.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_insert_and_delete() {
        let mut pkt = make_packet();
        let cfg = Config::default();

        // Insert
        let mut rng = StdRng::seed_from_u64(123);
        insert_random_byte(&mut pkt, &mut rng).unwrap();
        assert_eq!(pkt.len(), 5);

        // Delete
        delete_random_byte(&mut pkt, &mut rng).unwrap();
        assert_eq!(pkt.len(), 4);
    }

    #[test]
    fn test_substitute() {
        let mut pkt = make_packet();
        let cfg = Config::default();

        let mut rng = StdRng::seed_from_u64(999);
        substitute_random_bytes(&mut pkt, &mut rng, 2).unwrap();
        // Length should remain the same
        assert_eq!(pkt.len(), 4);
    }

    #[test]
    fn test_apply_mutations_with_config() {
        let mut pkt = make_packet();
        let cfg = Config {
            mutation_rate: 1.0,
            mutations_per_packet: Some(3),
            random_seed: 2021,
            bit_flip_weight: 2,
            byte_insert_weight: 1,
            byte_delete_weight: 1,
            substitute_weight: 1,
            bits_to_flip: 4,
            substitution_length: 2,
        };

        apply_mutations(&mut pkt, &cfg).unwrap();
        // After mutation, payload should differ
        assert_ne!(pkt.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}