use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub use crate::config::Config;
pub use crate::engine::mutate::Mutator;
pub use crate::engine::analyze::Analyzer;

/// The main fuzzing engine.
///
/// This struct coordinates the mutation and analysis stages,
/// maintaining state across iterations.  It is intentionally
/// lightweight so that it can be reused or wrapped in higher‑level
/// orchestration tools.
///
/// Author: Myroslav Mokhammad Abdeljawwad
pub struct Engine {
    target: PathBuf,
    mutator: Arc<Mutex<Box<dyn Mutator + Send>>>,
    analyzer: Arc<Mutex<Box<dyn Analyzer + Send>>>,
    config: Config,
}

impl Engine {
    /// Creates a new `Engine` instance.
    ///
    /// # Arguments
    ///
    /// * `target` - Path to the executable or binary under test.
    /// * `config` - Configuration parameters controlling fuzzing behaviour.
    pub fn new(target: impl Into<PathBuf>, config: Config) -> Result<Self, String> {
        let target_path = target.into();
        if !target_path.exists() || !target_path.is_file() {
            return Err(format!("Target path does not exist or is not a file: {}", target_path.display()));
        }

        // Initialise mutator and analyzer with default implementations.
        // In a real project these could be pluggable via trait objects.
        let mutator: Box<dyn Mutator + Send> = Box::new(crate::engine::mutate::DefaultMutator::new(&config));
        let analyzer: Box<dyn Analyzer + Send> = Box::new(crate::engine::analyze::DefaultAnalyzer::new());

        Ok(Self {
            target: target_path,
            mutator: Arc::new(Mutex::new(mutator)),
            analyzer: Arc::new(Mutex::new(analyzer)),
            config,
        })
    }

    /// Executes the fuzzing loop for a configured number of iterations.
    ///
    /// This method drives the mutation and analysis cycle, feeding
    /// mutated payloads to the target process and collecting crash
    /// traces.  Results are logged via the `log` crate.
    pub fn run(&self) -> Result<(), String> {
        use std::process::{Command, Stdio};

        for iteration in 0..self.config.iterations {
            let mutator = self.mutator.lock().map_err(|_| "Mutex poisoned".to_string())?;
            let payload = mutator.generate();

            // Run the target with the generated payload.
            let output = Command::new(&self.target)
                .arg(payload.as_str())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| format!("Failed to execute target: {}", e))?;

            // If the process crashed (non‑zero exit or signal), analyze.
            if !output.status.success() {
                let analyzer = self.analyzer.lock().map_err(|_| "Mutex poisoned".to_string())?;
                analyzer.process_crash(&payload, &output);
            }

            if iteration % 100 == 0 {
                log::info!("Iteration {}: processed payload of length {}", iteration, payload.len());
            }
        }

        Ok(())
    }
}

/// Re‑export submodules for external use.
pub mod mutate;
pub mod analyze;

mod mutate_impls; // optional internal module for helper structs
mod analyze_impls; // optional internal module for helper structs

// The following modules provide default implementations used by Engine.
// They are public to allow advanced users to replace them with custom logic.

/// Default mutator that applies simple random mutations.
pub struct DefaultMutator {
    config: Config,
}

impl DefaultMutator {
    pub fn new(config: &Config) -> Self {
        Self { config: config.clone() }
    }

    fn mutate(&self, data: &mut Vec<u8>) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..self.config.mutation_count {
            let idx = rng.gen_range(0..data.len());
            data[idx] ^= rng.gen::<u8>();
        }
    }
}

impl Mutator for DefaultMutator {
    fn generate(&mut self) -> String {
        // Start from the seed payload if provided.
        let mut payload = self.config.seed_payload.clone().unwrap_or_else(|| b"".to_vec());
        self.mutate(&mut payload);
        String::from_utf8_lossy(&payload).into_owned()
    }
}

/// Default analyzer that simply logs crash details.
/// In a real system this would parse stack traces, extract coverage,
/// and update mutation strategies.
pub struct DefaultAnalyzer;

impl DefaultAnalyzer {
    pub fn new() -> Self {
        Self
    }

    fn log_crash(payload: &str, output: &std::process::Output) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::error!("Crash detected!\nPayload: {}\nStderr:\n{}", payload, stderr);
    }
}

impl Analyzer for DefaultAnalyzer {
    fn process_crash(&self, payload: &str, output: &std::process::Output) {
        Self::log_crash(payload, output);
    }
}