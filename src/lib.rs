//! # Rust types for interacting with Zeek over WebSocket
//!
//! This library provides types for interacting with [Zeek](https://zeek.org)'s
//! WebSocket API.
//!
//! The main type of this crate is [`protocol::Binding`] which
//! models [Zeek's WebSocket
//! protocol](https://docs.zeek.org/projects/broker/en/master/web-socket.html). `Binding` depends
//! on [`tungstenite`](https://docs.rs/tungstenite/) and uses lower-level data types defined in
//! [`types`].
//!
//! Types in [`types`] can be used independently from `Binding` with any
//! backend.
//!
//! The lowest-level type of the API is [`types::Value`] which allows converting
//! between Zeek API types and Rust types, even user-defined types with [`ZeekType`].
//!
//! ## Feature flags
#![doc = document_features::document_features!()]

/// # Types of Zeek's WebSocket API
///
/// The main type of this module is [`Value`] which holds values of the Zeek API. Use its enum
/// variants to create values of specific types, e.g.,
///
/// ```
/// # use zeek_websocket::types::Value;
/// let value1 = Value::Count(0);
/// let value2 = Value::from(0u64);
/// assert_eq!(value1, value2);
/// ```
///
/// We provide implementations of [`TryFrom`] to go from Zeek values to Rust types, e.g.,
///
/// ```
/// # use zeek_websocket::types::Value;
/// assert_eq!(Value::Count(0).try_into(), Ok(0u64));
/// assert_eq!(u16::try_from(Value::Count(0)), Ok(0u16));
/// ```
///
/// User types can be serialized and deserialized with [`ZeekType`].
///
/// ```
/// # use zeek_websocket::{Value, ZeekType};
/// #[derive(ZeekType)]
/// struct X {
///     message: String,
///     count: u64,
/// }
///
/// let x = X { message: "Hello, world!".to_string(), count: 42 };
/// let value = Value::from(x);
/// let x = X::try_from(value);
/// assert!(matches!(x, Ok(X{ count: 42, .. })));
/// ```
pub mod types {
    #[doc(inline)]
    pub use zeek_websocket_types::*;
}
#[doc(inline)]
pub use types::*;

#[cfg(feature = "tungstenite")]
pub mod protocol;
#[cfg(feature = "tungstenite")]
#[doc(inline)]
pub use protocol::Binding;

#[cfg(feature = "tokio-client")]
pub mod client;

#[cfg(feature = "derive")]
#[doc(inline)]
pub use zeek_websocket_derive::ZeekType;
