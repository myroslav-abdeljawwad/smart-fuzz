# smart-fuzz

> AI‑guided fuzzing engine that learns from crash traces to generate smarter payloads.  
> Version: **0.1.0** – *crafted by Myroslav Mokhammad Abdeljawwad*

`smart_fuzz` is a library crate providing an extensible, data‑driven fuzzing framework.  
The public API is split into three logical layers:

* `engine` – core fuzzing logic (mutation & analysis)  
* `protocol` – packet abstraction for arbitrary protocols  
* `config` – runtime configuration

Below you’ll find a detailed reference of all exported items, including example usage snippets.

---

## 1. Top‑level crate (`src/lib.rs`)

```rust
pub mod engine;
pub mod protocol;
pub mod config;

use std::path::PathBuf;

/// Public entry point for starting a fuzzing session.
///
/// ```rust
/// use smart_fuzz::{EngineConfig, run_fuzzer};
///
/// let cfg = EngineConfig::default();
/// run_fuzzer(cfg).expect("Fuzzing failed");
/// ```
pub fn run_fuzzer(config: engine::config::EngineConfig) -> Result<(), Box<dyn std::error::Error>> {
    engine::run(config)
}
```

### `run_fuzzer`
* **Parameters** – `engine::config::EngineConfig`: fuzzing configuration.  
* **Returns** – `Result<(), Box<dyn Error>>`.  
* **Behavior** – Initializes the engine, loads initial seeds, starts mutation‑analysis loop.

---

## 2. Engine (`src/engine/mod.rs`)

The engine orchestrates the fuzzer: it reads seeds, mutates them, sends packets, analyzes responses, and learns new mutation strategies.

```rust
pub mod mutate;
pub mod analyze;
mod state;

use crate::protocol::packet::{Packet, PacketBuilder};
use crate::config::FuzzConfig;

/// Main fuzzing loop.
///
/// This function drives the entire fuzzer. It is intentionally synchronous to keep the API simple.
/// Internally it uses a thread pool for sending packets concurrently.
pub fn run(config: EngineConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = state::FuzzState::new(&config)?;
    let mut analyzer = analyze::Analyzer::new(state.clone());
    let mut mutator = mutate::Mutator::new();

    for seed in config.seeds.iter() {
        let packet = PacketBuilder::from_bytes(seed.clone()).build();
        state.add_seed(packet);
    }

    loop {
        let packet = state.next_mutation(&mutator)?;
        // send the packet over the network
        let response = send_packet(&packet, &config.target)?;

        analyzer.process_response(&response, &packet)?;

        if config.stop_condition.is_met() {
            break;
        }
    }

    Ok(())
}
```

### `EngineConfig`
```rust
/// Configuration for the fuzzing engine.
///
/// - `seeds`: initial payloads to start from.
/// - `target`: network target address (IP:port).
/// - `threads`: number of concurrent senders.
/// - `timeout_ms`: request timeout in milliseconds.
/// - `stop_condition`: optional stop condition (e.g., crash count, time limit).
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub seeds: Vec<Vec<u8>>,
    pub target: String,
    pub threads: usize,
    pub timeout_ms: u64,
    pub stop_condition: Option<StopCondition>,
}
```

### `StopCondition`
```rust
/// Stop condition for the fuzzer.
///
/// Currently supports either a maximum number of crashes or a time limit.
#[derive(Debug, Clone)]
pub enum StopCondition {
    MaxCrashes(u32),
    TimeLimit(std::time::Duration),
}
```

---

## 3. Mutation (`src/engine/mutate.rs`)

Provides deterministic and stochastic mutation strategies.

```rust
use crate::protocol::packet::Packet;

/// Trait for mutation operators.
pub trait Mutator: Send + Sync {
    fn mutate(&self, packet: &Packet) -> Vec<Packet>;
}

/// Simple XOR mutator – flips a random byte.
pub struct XorMutator;

impl Mutator for XorMutator {
    fn mutate(&self, packet: &Packet) -> Vec<Packet> {
        let mut mutated = packet.clone();
        if !mutated.payload.is_empty() {
            let idx = rand::random::<usize>() % mutated.payload.len();
            mutated.payload[idx] ^= 0xFF;
        }
        vec![mutated]
    }
}

/// Composite mutator that chains multiple strategies.
pub struct CompositeMutator {
    operators: Vec<Box<dyn Mutator>>,
}

impl CompositeMutator {
    pub fn new(operators: Vec<Box<dyn Mutator>>) -> Self {
        Self { operators }
    }

    pub fn apply(&self, packet: &Packet) -> Vec<Packet> {
        let mut results = Vec::new();
        for op in &self.operators {
            results.extend(op.mutate(packet));
        }
        results
    }
}
```

---

## 4. Analysis (`src/engine/analyze.rs`)

Analyzes responses, detects crashes, and updates mutation probabilities.

```rust
use crate::protocol::packet::{Packet, Response};
use std::collections::HashMap;

/// Analyzer holds crash statistics and informs the mutator.
pub struct Analyzer {
    crash_counts: HashMap<String, u32>,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            crash_counts: HashMap::new(),
        }
    }

    /// Process a response from the target.
    ///
    /// - Detects crashes by looking for known crash signatures in the payload.
    /// - Updates internal statistics.
    pub fn process_response(&mut self, resp: &Response, pkt: &Packet) -> Result<(), Box<dyn std::error::Error>> {
        if Self::is_crash(resp)? {
            let key = String::from_utf8_lossy(&pkt.payload).to_string();
            *self.crash_counts.entry(key).or_insert(0) += 1;
        }
        Ok(())
    }

    fn is_crash(resp: &Response) -> Result<bool, Box<dyn std::error::Error>> {
        // Simple heuristic: payload contains "SIGSEGV" or similar.
        let text = String::from_utf8_lossy(&resp.payload);
        Ok(text.contains("SIGSEGV") || text.contains("EXCEPTION"))
    }

    /// Retrieve the most frequent crash signature.
    pub fn top_crash(&self) -> Option<(String, u32)> {
        self.crash_counts
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, v)| (k.clone(), *v))
    }
}
```

---

## 5. Protocol (`src/protocol/packet.rs`)

Represents a generic packet and its builder.

```rust
use std::io::{self, Write};

/// Raw packet payload.
#[derive(Debug, Clone)]
pub struct Packet {
    pub payload: Vec<u8>,
}

impl Packet {
    /// Send the packet to the given socket address.
    ///
    /// Returns a `Response` containing whatever data was received back.
    pub fn send(&self, addr: &str) -> io::Result<Response> {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.send_to(&self.payload, addr)?;
        let mut buf = [0u8; 4096];
        let (len, _) = sock.recv_from(&mut buf)?;
        Ok(Response {
            payload: buf[..len].to_vec(),
        })
    }
}

/// Builder for creating packets from raw bytes.
pub struct PacketBuilder {
    payload: Vec<u8>,
}

impl PacketBuilder {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { payload: bytes }
    }

    /// Append a field to the packet.
    pub fn append_field(mut self, field: &[u8]) -> Self {
        self.payload.extend_from_slice(field);
        self
    }

    /// Finalize and produce a `Packet`.
    pub fn build(self) -> Packet {
        Packet { payload: self.payload }
    }
}

/// Response from the target after sending a packet.
#[derive(Debug, Clone)]
pub struct Response {
    pub payload: Vec<u8>,
}
```

---

## 6. Configuration (`src/config.rs`)

Defines runtime configuration for the fuzzer.

```rust
use std::path::PathBuf;

/// Global configuration loaded from a TOML/YAML file.
///
/// Example YAML:
/// ```yaml
/// seeds:
///   - "0xdeadbeef"
/// target: "127.0.0.1:9999"
/// threads: 4
/// timeout_ms: 500
/// stop_condition:
///   max_crashes: 10
/// ```
#[derive(Debug, Deserialize)]
pub struct FuzzConfig {
    pub seeds: Vec<String>,
    pub target: String,
    pub threads: usize,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub stop_condition: Option<StopConditionConfig>,
}

fn default_timeout() -> u64 { 500 }

#[derive(Debug, Deserialize)]
pub enum StopConditionConfig {
    MaxCrashes(u32),
    TimeLimitSeconds(u64),
}
```

---

## 7. Tests (`tests/fuzz_test.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use smart_fuzz::protocol::packet::{Packet, PacketBuilder};

    #[test]
    fn test_packet_builder() {
        let packet = PacketBuilder::from_bytes(vec![0x01, 0x02])
            .append_field(&[0x03])
            .build();
        assert_eq!(packet.payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_xor_mutator() {
        use smart_fuzz::engine::mutate::{XorMutator, Mutator};

        let original = Packet { payload: vec![0xAA] };
        let mutator = XorMutator;
        let mutated = mutator.mutate(&original);
        assert_eq!(mutated.len(), 1);
        assert_ne!(mutated[0].payload[0], original.payload[0]);
    }
}
```

---

## 8. Example (`examples/example_protocol.yaml`)

```yaml
seeds:
  - "01020304"
target: "192.168.1.100:8080"
threads: 2
timeout_ms: 300
stop_condition:
  max_crashes: 5
```

---

## 9. Cargo.toml (excerpt)

```toml
[package]
name = "smart-fuzz"
version = "0.1.0"
edition = "2021"

[dependencies]
rand = { version = "0.8", features = ["std"] }
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
```

---