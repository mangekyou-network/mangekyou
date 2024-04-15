// Copyright (c) 2022, Mangekyou Network, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

// #[cfg(test)]
// #[path = "tests/hash_tests.rs"]
// pub mod hash_tests;

#[cfg(test)]
#[path = "tests/encoding_tests.rs"]
pub mod encoding_tests;

#[cfg(test)]
#[path = "tests/ristretto255_tests.rs"]
pub mod ristretto255_tests;

#[cfg(test)]
#[path = "tests/test_helpers.rs"]
pub mod test_helpers;

#[cfg(test)]
#[path = "tests/utils_tests.rs"]
pub mod utils_tests;

pub mod traits;

pub mod encoding;
pub mod error;
pub mod groups;
pub mod hash;
pub mod serde_helpers;
pub mod utils;
pub mod kamui_vrf;

/// This module contains unsecure cryptographic primitives. The purpose of this library is to allow seamless
/// benchmarking of systems without taking into account the cost of cryptographic primitives - and hence
/// providing a theoretical maximal throughput that a system could achieve if the cost of crypto is optimized
/// away.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
#[cfg(feature = "unsecure_schemes")]
pub mod unsecure;
