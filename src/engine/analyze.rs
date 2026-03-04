/// Smart‑Fuzz crash analysis module.
/// 
/// This module inspects crash traces and suggests minimal mutations to the original
/// payload that might trigger deeper execution paths.  The heuristics are intentionally
/// simple – they serve as a starting point for future machine‑learning integration.
///
/// Author: Myroslav Mokhammad Abdeljawwad

use std::fmt;
use std::error::Error;

use crate::engine::mutate::{Mutation, Mutator};

/// Result of analyzing a crash trace.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Human readable explanation of why the analysis concluded as such.
    pub description: String,
    /// Suggested mutation to apply to the original payload.
    pub suggestion: Option<Mutation>,
}

impl fmt::Display for AnalysisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Analysis Result: {}", self.description)?;
        if let Some(ref m) = self.suggestion {
            write!(f, "Suggested mutation: {:?}", m)
        } else {
            write!(f, "No suggestion")
        }
    }
}

impl Error for AnalysisResult {}

/// Analyzes a crash trace and returns an `AnalysisResult`.
///
/// # Arguments
///
/// * `trace` - The textual stack or error trace reported by the target.
/// * `original_payload` - The byte sequence that caused the crash.
///
/// # Returns
///
/// An `AnalysisResult` containing a description of the analysis and, if applicable,
/// a mutation suggestion.
pub fn analyze_trace(trace: &str, original_payload: &[u8]) -> AnalysisResult {
    // Basic validation
    let trace = trace.trim();
    if trace.is_empty() {
        return AnalysisResult {
            description: "Empty crash trace provided".to_string(),
            suggestion: None,
        };
    }

    // Heuristic 1: Null pointer dereference – add a null byte at the end.
    if trace.contains("null pointer") || trace.contains("dereference") {
        let mutator = Mutator::new();
        let mutation = mutator.append_byte(original_payload, 0x00);
        return AnalysisResult {
            description:
                "Detected potential null‑pointer dereference; adding NUL byte may bypass guard".to_string(),
            suggestion: Some(mutation),
        };
    }

    // Heuristic 2: Index out of bounds – increment the last byte to force a different branch.
    if trace.contains("index") && trace.contains("out of bounds") {
        let mutator = Mutator::new();
        let mutation = mutator.increment_last_byte(original_payload);
        return AnalysisResult {
            description:
                "Detected index out‑of‑bounds error; incrementing last byte may explore new paths".to_string(),
            suggestion: Some(mutation),
        };
    }

    // Heuristic 3: Unexpected EOF – pad with a repeated pattern.
    if trace.contains("unexpected eof") || trace.contains("read past end") {
        let mutator = Mutator::new();
        let mutation = mutator.pad_with_pattern(original_payload, &[0xAA; 4]);
        return AnalysisResult {
            description:
                "Detected unexpected EOF; padding with pattern may expose hidden logic".to_string(),
            suggestion: Some(mutation),
        };
    }

    // Default case – no specific insight.
    AnalysisResult {
        description: "No actionable patterns detected in trace".to_string(),
        suggestion: None,
    }
}

/// Applies the suggested mutation to the original payload.
///
/// # Arguments
///
/// * `original_payload` - The original byte sequence.
/// * `analysis_result` - Result from `analyze_trace`.
///
/// # Returns
///
/// A new vector of bytes with the mutation applied, or a clone of the original if no mutation.
pub fn apply_suggestion(
    original_payload: &[u8],
    analysis_result: &AnalysisResult,
) -> Vec<u8> {
    match &analysis_result.suggestion {
        Some(mutation) => mutation.apply(original_payload),
        None => original_payload.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_pointer_detection() {
        let trace = "Segmentation fault: 11\n   at dereference ...";
        let payload = b"payload";
        let res = analyze_trace(trace, payload);
        assert!(res.suggestion.is_some());
        let mutated = apply_suggestion(payload, &res);
        assert_eq!(&mutated[..], b"payload\x00");
    }

    #[test]
    fn test_index_out_of_bounds_detection() {
        let trace = "panic: index out of bounds";
        let payload = b"\x01\x02\x03";
        let res = analyze_trace(trace, payload);
        assert!(res.suggestion.is_some());
        let mutated = apply_suggestion(payload, &res);
        assert_eq!(&mutated[..], b"\x01\x02\x04");
    }

    #[test]
    fn test_no_detection() {
        let trace = "normal error message";
        let payload = b"data";
        let res = analyze_trace(trace, payload);
        assert!(res.suggestion.is_none());
        let mutated = apply_suggestion(payload, &res);
        assert_eq!(&mutated[..], b"data");
    }

    #[test]
    fn test_eof_detection() {
        let trace = "unexpected eof while reading";
        let payload = b"\x10\x20";
        let res = analyze_trace(trace, payload);
        assert!(res.suggestion.is_some());
        let mutated = apply_suggestion(payload, &res);
        // padded with 0xAA pattern
        assert_eq!(&mutated[..], b"\x10\x20\xaa\xaa\xaa\xaa");
    }
}