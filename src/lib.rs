//! # Rust types for interacting with Zeek over WebSocket
//!
//! This library provides types for interacting with [Zeek](https://zeek.org)'s
//! WebSocket API.
//!
//! The main type of this crate is [`protocol::Connection`] which
//! models Zeek's WebSocket protocol. `Connection` depends on
//! [`tungstenite`](https://docs.rs/tungstenite/) and uses lower-level data types defined in
//! [`types`].
//!
//! Types in [`types`] can be used independently from `Connection` with any
//! backend.
//!
//! The lowest-level type of the API is [`types::Value`] which allows converting
//! between Zeek API types and Rust types.
//!
//! ## Feature flags
#![doc = document_features::document_features!()]

pub mod types;
pub use types::*;

#[cfg(feature = "tungstenite")]
pub mod protocol;
#[cfg(feature = "tungstenite")]
pub use protocol::Connection;
