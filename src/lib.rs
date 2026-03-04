//! # smart-fuzz
//!
//! AI‑guided fuzzing engine that learns from crash traces to generate smarter payloads.
//!
//! The crate is split into several modules:
//! * `engine` – core fuzzing logic (mutation, analysis, orchestration)
//! * `protocol` – packet parsing and serialization helpers
//! * `config` – configuration handling
//!
//! ## Usage example
//! ```rust,no_run
//! use smart_fuzz::{Engine, Config};
//!
//! let cfg = Config::default();
//! let mut engine = Engine::new(cfg).expect("Failed to create engine");
//! engine.run().expect("Fuzzing failed");
//! ```
//!
//! **Author:** Myroslav Mokhammad Abdeljawwad

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub use crate::config::Config;
pub use crate::engine::Engine;
pub use crate::protocol::packet::{Packet, PacketError};

/// Public API re‑exports for convenience
pub mod prelude {
    pub use super::{Config, Engine, Packet, PacketError};
}

mod engine;
mod protocol;
mod config;

/// Error type used across the library.
/// Wraps underlying errors from different subsystems.
#[derive(Debug)]
pub enum SmartFuzzError {
    /// IO error when loading configuration or crash traces
    Io(std::io::Error),
    /// Serialization / deserialization issue
    Serde(serde_yaml::Error),
    /// Protocol parsing error
    Packet(PacketError),
    /// Analysis subsystem returned an error
    Analyze(String),
    /// Mutation subsystem failed
    Mutate(String),
    /// Generic wrapper for other errors
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<std::io::Error> for SmartFuzzError {
    fn from(e: std::io::Error) -> Self { SmartFuzzError::Io(e) }
}
impl From<serde_yaml::Error> for SmartFuzzError {
    fn from(e: serde_yaml::Error) -> Self { SmartFuzzError::Serde(e) }
}
impl From<PacketError> for SmartFuzzError {
    fn from(e: PacketError) -> Self { SmartFuzzError::Packet(e) }
}

impl std::fmt::Display for SmartFuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmartFuzzError::Io(e) => write!(f, "IO error: {}", e),
            SmartFuzzError::Serde(e) => write!(f, "YAML parse error: {}", e),
            SmartFuzzError::Packet(e) => write!(f, "Packet error: {}", e),
            SmartFuzzError::Analyze(msg) => write!(f, "Analysis failed: {}", msg),
            SmartFuzzError::Mutate(msg) => write!(f, "Mutation failed: {}", msg),
            SmartFuzzError::Other(err) => write!(f, "Unknown error: {}", err),
        }
    }
}
impl std::error::Error for SmartFuzzError {}

/// Load a configuration file from the given path.
/// Returns `Err` if the file does not exist or is malformed.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config, SmartFuzzError> {
    let cfg_str = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&cfg_str)?)
}

/// Utility to write a configuration back to disk in YAML format.
pub fn write_config<P: AsRef<Path>>(path: P, cfg: &Config) -> Result<(), SmartFuzzError> {
    let yaml = serde_yaml::to_string(cfg)?;
    std::fs::write(path, yaml)?;
    Ok(())
}

/// A simple helper that returns the default configuration file path.
/// Typically located in `~/.config/smart_fuzz/config.yaml`.
pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("smart_fuzz")
        .join("config.yaml")
}

/// High‑level API that runs the fuzzing engine.
/// It spawns a background thread for mutation and analysis, then
/// streams packets from the target until the user cancels.
pub fn run_default_engine() -> Result<(), SmartFuzzError> {
    let cfg = load_config(default_config_path())?;
    let mut engine = Engine::new(cfg)?;
    engine.run()
}

/// Re‑exporting modules for external users to access internals if needed
pub mod engine;
pub mod protocol;
pub mod config;

/// Tests for the public API of `smart_fuzz`.
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    /// Create a temporary YAML configuration file.
    fn temp_config_file(content: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        write!(tmp.as_file_mut(), "{}", content).expect("Failed to write config");
        tmp
    }

    #[test]
    fn test_load_and_write_config() {
        let cfg_yaml = r#"
            target: "127.0.0.1:8080"
            max_iterations: 1000
            mutation_strategy:
              - random
              - bit_flip
        "#;
        let tmp_cfg = temp_config_file(cfg_yaml);
        let cfg = load_config(tmp_cfg.path()).expect("Failed to load config");
        assert_eq!(cfg.target, "127.0.0.1:8080");
        assert_eq!(cfg.max_iterations, 1000);

        // Write back
        let out_path = tmp_cfg.path().with_extension("out.yaml");
        write_config(&out_path, &cfg).expect("Failed to write config");

        let written = fs::read_to_string(out_path).expect("Read written file");
        assert!(written.contains("target: \"127.0.0.1:8080\""));
    }

    #[test]
    fn test_default_engine_runs_once() {
        // Create a dummy target that immediately exits.
        use std::{process::Command, thread};

        let script = r#"
            #!/usr/bin/env bash
            exit 0
        "#;
        let tmp_script = tempfile::NamedTempFile::new().expect("tmp file");
        fs::write(tmp_script.path(), script).expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(tmp_script.path()).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(tmp_script.path(), perms).unwrap();
        }

        // Run the engine pointing to this script
        let cfg_yaml = format!(
            r#"
            target: "{}"
            max_iterations: 1
            mutation_strategy:
              - random
            "#,
            tmp_script.path().display()
        );
        let tmp_cfg = temp_config_file(&cfg_yaml);
        let mut engine = Engine::new(load_config(tmp_cfg.path()).unwrap())
            .expect("Failed to create engine");
        engine.run().expect("Engine run failed");
    }

    #[test]
    fn test_packet_roundtrip() {
        // Construct a packet, serialize, parse back
        use crate::protocol::packet::{Packet, PacketType};

        let payload = b"hello".to_vec();
        let pkt = Packet::new(PacketType::Command, 42, payload.clone());
        let bytes = pkt.to_bytes();

        let parsed = Packet::from_bytes(&bytes).expect("Failed to parse packet");
        assert_eq!(parsed.command_id(), 42);
        assert_eq!(parsed.payload(), &payload);
    }
}