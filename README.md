# smart‑fuzz  
**AI‑guided fuzzing engine that learns from crash traces to generate smarter payloads**

---

## About

Built by **Myroslav Mokhammad Abdeljawwad** to solve the age‑old problem of “guess‑and‑try” fuzzing, *smart‑fuzz* uses a lightweight neural model to analyse crash traces and evolve mutation strategies on the fly. The result is a Rust library you can drop into any protocol implementation and watch it learn how to hit the edge cases faster than traditional tools.

> *“When I first saw the flood of false positives in our fuzz runs, I realized we were shouting into a void.”* – Myroslav Mokhammad Abdeljawwad

---

## Features

- **Crash‑trace learning** – Extracts signal from stack traces to guide mutation.
- **Modular engine** – `engine::mutate`, `engine::analyze` and protocol packet parsing in separate modules.
- **Zero‑dependency API** – Works out of the box with only `serde` for config and `rand`.
- **Configurable via YAML** – Load custom packet schemas from files (see `examples/example_protocol.yaml`).
- **Rust 2021** – Safe, fast, and fully documented (check `docs/api.md`).

---

## Installation

```bash
cargo add smart-fuzz
```

Or clone the repo and build locally:

```bash
git clone https://github.com/yourname/smart-fuzz.git
cd smart-fuzz
cargo build --release
```

The library is published on crates.io, so adding it as a dependency will pull in `serde`, `rand` and `regex` automatically.

---

## Usage

### 1. Load a protocol definition

```rust
use smart_fuzz::config::ProtocolConfig;
use std::fs;

let yaml = fs::read_to_string("examples/example_protocol.yaml").unwrap();
let cfg: ProtocolConfig = serde_yaml::from_str(&yaml).expect("Invalid YAML");
```

### 2. Create the engine and run a fuzz cycle

```rust
use smart_fuzz::engine::{Engine, EngineOptions};

let mut engine = Engine::new(cfg, EngineOptions::default());
for _ in 0..100 {
    let payload = engine.mutate();
    // send `payload` to target, collect crash trace ...
    let trace = get_crash_trace();   // placeholder for your own collector
    engine.analyze(trace);
}
```

### 3. Inspect the best seeds

```rust
let best_seeds = engine.best_seeds();
println!("Top payloads: {:?}", best_seeds);
```

---

## Contributing

I welcome any feedback or pull requests!  
1. Fork the repo and create a feature branch.  
2. Run `cargo test` to ensure everything passes.  
3. Open a PR with a clear description of your changes.

If you’re new to Rust or fuzzing, feel free to ask questions in the issues tab—I’m happy to help.

---

## License

MIT © 2024 Myroslav Mokhammad Abdeljawwad

--- 

### See Also

- [Building Reliable Software Systems: Lessons Learned from Engineering Culture in Germany](https://dev.to/myroslavmokhammadabd/building-reliable-software-systems-lessons-learned-from-engineering-culture-in-germany-50gd) – The blog post that inspired this project.