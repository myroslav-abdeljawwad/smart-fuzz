use std::error::Error;
use std::fs;

use smart_fuzz::config::Config;
use smart_fuzz::engine::{Analyzer, Mutator};
use smart_fuzz::protocol::packet::Packet;

/// The tests module for the `smart-fuzz` crate.
///
/// This file demonstrates how to use the public API of the library:
/// * Load a configuration from a YAML file.
/// * Create a packet payload using the mutator.
/// * Simulate a crash trace and analyze it with the analyzer.
/// * Verify that the mutation algorithm produces valid packets
///   and that the analyzer correctly identifies potential bugs.
///
/// Author: Myroslav Mokhammad Abdeljawwad
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Helper to create a temporary configuration file.
    fn write_temp_config(contents: &str) -> Result<std::path::PathBuf, Box<dyn Error>> {
        let dir = tempdir()?;
        let path = dir.path().join("config.yaml");
        fs::write(&path, contents)?;
        Ok(path)
    }

    /// Test that a valid configuration can be parsed and used to create a mutator.
    #[test]
    fn test_config_parsing_and_mutator_creation() -> Result<(), Box<dyn Error>> {
        let yaml = r#"
            fuzz:
              seed: 42
              max_payload_size: 128
            engine:
              mutation_strategy: "gaussian"
        "#;

        let config_path = write_temp_config(yaml)?;
        let cfg = Config::from_file(&config_path)?;

        assert_eq!(cfg.fuzz.seed, 42);
        assert_eq!(cfg.fuzz.max_payload_size, 128);

        let mutator = Mutator::new(cfg.clone())?;
        // The mutator should be able to produce a packet of the expected size.
        let payload = mutator.generate_payload()?;
        assert!(!payload.is_empty());
        assert!(payload.len() <= cfg.fuzz.max_payload_size as usize);
        Ok(())
    }

    /// Test that the mutator produces deterministic output when using a fixed seed.
    #[test]
    fn test_mutator_determinism_with_seed() -> Result<(), Box<dyn Error>> {
        let yaml = r#"
            fuzz:
              seed: 12345
              max_payload_size: 64
            engine:
              mutation_strategy: "uniform"
        "#;

        let config_path = write_temp_config(yaml)?;
        let cfg1 = Config::from_file(&config_path)?;
        let mutator1 = Mutator::new(cfg1.clone())?;
        let payload1 = mutator1.generate_payload()?;

        // Recreate with the same configuration and ensure identical output.
        let cfg2 = Config::from_file(&config_path)?;
        let mutator2 = Mutator::new(cfg2)?;
        let payload2 = mutator2.generate_payload()?;

        assert_eq!(payload1, payload2);
        Ok(())
    }

    /// Test that a malformed packet causes the analyzer to report an error.
    #[test]
    fn test_analyzer_with_invalid_packet() -> Result<(), Box<dyn Error>> {
        // Create a payload that is too short to be parsed as a valid packet.
        let invalid_payload = vec![0x00; 3]; // Assuming minimum header size > 3
        let analyzer = Analyzer::new()?;

        match analyzer.analyze(&invalid_payload) {
            Ok(_) => panic!("Analyzer should fail on an invalid packet"),
            Err(e) => assert!(e.to_string().contains("parsing")),
        }
        Ok(())
    }

    /// Test that a valid packet is correctly parsed and analyzed.
    #[test]
    fn test_analyzer_with_valid_packet() -> Result<(), Box<dyn Error>> {
        // Build a simple, well-formed packet using the protocol API.
        let mut packet = Packet::new();
        packet.set_header(b"HEAD");
        packet.set_payload(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let payload = packet.serialize()?;
        assert!(payload.len() > 0);

        let analyzer = Analyzer::new()?;
        let analysis_result = analyzer.analyze(&payload)?;

        // The analysis should not report any fatal errors for this trivial packet.
        assert!(!analysis_result.fatal_errors);
        Ok(())
    }

    /// Test the end-to-end fuzzing loop: generate payloads, simulate crashes,
    /// and analyze them. Verify that the engine keeps track of seen crashes
    /// and does not duplicate analysis on identical traces.
    #[test]
    fn test_fuzz_loop_and_crash_tracking() -> Result<(), Box<dyn Error>> {
        let yaml = r#"
            fuzz:
              seed: 9999
              max_payload_size: 256
            engine:
              mutation_strategy: "gaussian"
        "#;

        let config_path = write_temp_config(yaml)?;
        let cfg = Config::from_file(&config_path)?;

        let mutator = Mutator::new(cfg.clone())?;
        let analyzer = Analyzer::new()?;

        // Simulate a crash trace (here we just reuse the payload as the trace).
        let mut seen_traces = std::collections::HashSet::new();

        for _ in 0..10 {
            let payload = mutator.generate_payload()?;
            let analysis = analyzer.analyze(&payload)?;

            if analysis.fatal_errors {
                // Treat fatal errors as a crash.
                assert!(seen_traces.insert(payload.clone()));
            } else {
                // Non-fatal: ensure we don't record it as a crash.
                assert!(!seen_traces.contains(&payload));
            }
        }

        // Ensure that the set contains only unique traces with fatal errors.
        for trace in seen_traces {
            let analysis = analyzer.analyze(&trace)?;
            assert!(analysis.fatal_errors);
        }

        Ok(())
    }
}