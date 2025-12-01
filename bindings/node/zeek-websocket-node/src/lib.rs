//! Node API for interacting with the Zeek WebSocket API.

#![deny(clippy::all)]
#![allow(dead_code)]

use std::{net::IpAddr, str::FromStr};

use napi::bindgen_prelude::{BigInt, Buffer, BufferSlice};
use napi_derive::napi;
use thiserror::Error;
use zeek_websocket::DateTime;

/// Message type of the Zeek WebSocket API.
#[napi]
pub enum Message {
    /// Ack sent by Zeek when a client was subscribed.
    Ack { endpoint: String, version: String },
    /// Event sent over the Zeek API.
    Event { topic: String, event: Event },
    /// Error sent over the Zeek API.
    Error { code: String, context: String },
}

impl TryFrom<Message> for zeek_websocket::Message {
    type Error = Error;

    fn try_from(value: Message) -> Result<Self, Error> {
        Ok(match value {
            Message::Ack { endpoint, version } => {
                zeek_websocket::Message::Ack { endpoint, version }
            }
            Message::Event { topic, event } => {
                let event: zeek_websocket::Event = event.try_into()?;
                zeek_websocket::Message::new_data(topic, event)
            }
            Message::Error { code, context } => zeek_websocket::Message::Error { code, context },
        })
    }
}

/// A Zeek event.
#[napi(object)]
pub struct Event {
    /// The name of the event.
    pub name: String,
    /// Arguments passed to the event.
    pub args: Vec<Value>,
    /// Metadata associated with the event.
    pub metadata: Vec<Value>,
}

impl TryFrom<zeek_websocket::Event> for Event {
    type Error = Error;

    fn try_from(value: zeek_websocket::Event) -> Result<Self, Self::Error> {
        let zeek_websocket::Event {
            name,
            args,
            metadata,
        } = value;
        let args = args
            .into_iter()
            .map(Value::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let metadata = metadata
            .into_iter()
            .map(Value::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            name,
            args,
            metadata,
        })
    }
}

impl TryFrom<Event> for zeek_websocket::Event {
    type Error = Error;

    fn try_from(
        Event {
            name,
            args,
            metadata,
        }: Event,
    ) -> Result<Self, Self::Error> {
        let args = args
            .into_iter()
            .map(zeek_websocket::Value::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let metadata = metadata
            .into_iter()
            .map(zeek_websocket::Value::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            name,
            args,
            metadata,
        })
    }
}

/// Deserialize a given JSON payload to a [`Message`].
#[napi]
pub fn deserialize_json(json: String) -> napi::Result<Message> {
    let message: zeek_websocket::Message =
        serde_json::from_str(&json).map_err(|e| Error::UnsupportedMessagePayload(e.to_string()))?;
    Ok(match message {
        zeek_websocket::Message::Ack { endpoint, version } => Message::Ack { endpoint, version },
        zeek_websocket::Message::Error { code, context } => Message::Error { code, context },
        zeek_websocket::Message::DataMessage { topic, data } => match data {
            zeek_websocket::Data::Event(event) => Message::Event {
                topic,
                event: event.try_into()?,
            },
            zeek_websocket::Data::Other(other) => Err(Error::UnsupportedMessagePayload(format!(
                "expected event, got '{other:?}'"
            )))?,
        },
    })
}

/// Serialize a [`Message`] to JSON.
#[napi]
pub fn serialize_json(message: Message) -> napi::Result<String> {
    let value: zeek_websocket::Message = message.try_into()?;
    Ok(serde_json::to_string(&value)
        .map_err(|e| Error::UnsupportedMessagePayload(e.to_string()))?)
}

/// A basic value sent over the Zeek API.
#[napi]
pub enum Value {
    None,
    Boolean { value: bool },
    Count { value: BigInt },
    Integer { value: i64 },
    Real { value: f64 },
    Timespan { nanos: i64 },
    Timestamp { nanos: i64 },
    String { value: String },
    EnumValue { value: String },
    Address { value: String },
    Subnet { value: String },
    Port { number: u16, protocol: Protocol },
    Vector { value: Vec<Value> },
    Set { value: Vec<Value> },
    Table { value: Vec<(Value, Value)> },
}

impl TryFrom<Value> for zeek_websocket::Value {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(match value {
            Value::None => zeek_websocket::Value::None,
            Value::Boolean { value } => zeek_websocket::Value::Boolean(value),
            Value::Count { value } => {
                let (_, value, true) = value.get_u64() else {
                    return Err(Error::NotRespresentable(format!("{value:?}")));
                };
                zeek_websocket::Value::Count(value)
            }
            Value::Integer { value } => zeek_websocket::Value::Integer(value),
            Value::Real { value } => zeek_websocket::Value::Real(value),
            Value::String { value } => zeek_websocket::Value::String(value),
            Value::EnumValue { value } => zeek_websocket::Value::EnumValue(value),
            Value::Timespan { nanos } => {
                let nanos_ = nanos as f64;

                let secs = (nanos_ / 1e9).trunc();
                let nanos_ = nanos_ - secs * 1e9;

                zeek_websocket::Value::Timespan(
                    zeek_websocket::TimeDelta::new(secs as i64, nanos_ as u32)
                        .ok_or_else(|| Error::NotRespresentable(nanos.to_string()))?,
                )
            }
            Value::Timestamp { nanos } => zeek_websocket::Value::Timestamp(
                DateTime::from_timestamp_nanos(nanos).naive_local(),
            ),
            Value::Vector { value } => zeek_websocket::Value::Vector(
                value
                    .into_iter()
                    .map(zeek_websocket::Value::try_from)
                    .collect::<Result<_, _>>()?,
            ),
            Value::Set { value } => zeek_websocket::Value::Set(
                value
                    .into_iter()
                    .map(zeek_websocket::Value::try_from)
                    .collect::<Result<_, _>>()?,
            ),
            Value::Table { value } => zeek_websocket::Value::Table(
                value
                    .into_iter()
                    .map(|(k, v)| {
                        Ok(zeek_websocket::TableEntry::new(
                            k.try_into()?,
                            v.try_into()?,
                        ))
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Value::Address { value } => zeek_websocket::Value::Address(
                IpAddr::from_str(&value).map_err(|e| Error::NotRespresentable(e.to_string()))?,
            ),
            Value::Subnet { value } => zeek_websocket::Value::Subnet(
                zeek_websocket::IpNetwork::from_str(&value)
                    .map_err(|e| Error::NotRespresentable(e.to_string()))?,
            ),
            Value::Port { number, protocol } => {
                zeek_websocket::Value::Port(zeek_websocket::Port::new(number, protocol.into()))
            }
        })
    }
}

impl TryFrom<zeek_websocket::Value> for Value {
    type Error = Error;

    fn try_from(value: zeek_websocket::Value) -> Result<Self, Self::Error> {
        Ok(match value {
            zeek_websocket::Value::None => Value::None,
            zeek_websocket::Value::Boolean(x) => Value::Boolean { value: x },
            zeek_websocket::Value::Count(x) => Value::Count {
                value: BigInt::from(x),
            },
            zeek_websocket::Value::Integer(x) => Value::Integer { value: x },
            zeek_websocket::Value::Real(x) => Value::Real { value: x },
            zeek_websocket::Value::String(x) => Value::String { value: x },
            zeek_websocket::Value::EnumValue(x) => Value::EnumValue { value: x },
            zeek_websocket::Value::Vector(x) => Value::Vector {
                value: x
                    .into_iter()
                    .map(Value::try_from)
                    .collect::<Result<_, _>>()?,
            },
            zeek_websocket::Value::Set(x) => Value::Set {
                value: x
                    .into_iter()
                    .map(Value::try_from)
                    .collect::<Result<_, _>>()?,
            },
            zeek_websocket::Value::Table(x) => Value::Table {
                value: x
                    .into_iter()
                    .map(|zeek_websocket::TableEntry { key, value }| {
                        Ok((key.try_into()?, value.try_into()?))
                    })
                    .collect::<Result<_, _>>()?,
            },
            zeek_websocket::Value::Port(port) => Value::Port {
                number: port.number(),
                protocol: port.protocol().into(),
            },
            zeek_websocket::Value::Address(addr) => Value::Address {
                value: addr.to_string(),
            },
            zeek_websocket::Value::Subnet(addr) => Value::Subnet {
                value: addr.to_string(),
            },
            zeek_websocket::Value::Timespan(dt) => {
                let nanos = dt
                    .num_nanoseconds()
                    .ok_or_else(|| Error::NotRespresentable(format!("{dt}")))?;

                Value::Timespan { nanos }
            }
            zeek_websocket::Value::Timestamp(t) => {
                let nanos = t
                    .and_utc()
                    .timestamp_nanos_opt()
                    .ok_or_else(|| Error::NotRespresentable(format!("{t}")))?;

                Value::Timestamp { nanos }
            }
        })
    }
}

/// Protocols understood by Zeek.
#[napi]
#[derive(Clone, Copy)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

impl From<Protocol> for zeek_websocket::Protocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::TCP => zeek_websocket::Protocol::TCP,
            Protocol::UDP => zeek_websocket::Protocol::UDP,
            Protocol::ICMP => zeek_websocket::Protocol::ICMP,
            Protocol::UNKNOWN => zeek_websocket::Protocol::UNKNOWN,
        }
    }
}

impl From<zeek_websocket::Protocol> for Protocol {
    fn from(value: zeek_websocket::Protocol) -> Self {
        match value {
            zeek_websocket::Protocol::TCP => Protocol::TCP,
            zeek_websocket::Protocol::UDP => Protocol::UDP,
            zeek_websocket::Protocol::ICMP => Protocol::ICMP,
            zeek_websocket::Protocol::UNKNOWN => Protocol::UNKNOWN,
        }
    }
}

/// Possible errors for the Node API.
#[derive(Error, Debug)]
pub enum Error {
    #[error("value '{0}' not representable in Zeek")]
    NotRespresentable(String),

    #[error("unsupported message payload: {0}")]
    UnsupportedMessagePayload(String),

    #[error("message handling failed: {0}")]
    HandlingFailed(String),

    #[error("receive failed: {0}")]
    ReceiveFailed(String),
}

impl From<Error> for napi::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::NotRespresentable(error)
            | Error::ReceiveFailed(error)
            | Error::HandlingFailed(error)
            | Error::UnsupportedMessagePayload(error) => Self::from_reason(error),
        }
    }
}

/// Sans-I/O wrapper for the Zeek WebSocket protocol.
#[napi]
struct ProtocolBinding(zeek_websocket::Binding);

#[napi]
impl ProtocolBinding {
    #[napi(constructor)]
    pub fn new(subscriptions: Vec<String>) -> Self {
        Self(zeek_websocket::Binding::new(subscriptions))
    }

    /// Handle received message.
    #[napi]
    pub fn handle_incoming(&mut self, data: BufferSlice) -> napi::Result<()> {
        let message = serde_json::from_slice(&data).map_err(|e| {
            Error::UnsupportedMessagePayload(format!("data payload not understood: {e}"))
        })?;

        self.0
            .handle_incoming(message)
            .map_err(|e| Error::HandlingFailed(format!("failed to handle message: {e}")))?;
        Ok(())
    }

    /// Get next data enqueued for sending.
    #[napi]
    pub fn outgoing(&mut self) -> Option<Buffer> {
        Some(Buffer::from(self.0.outgoing()?.as_ref()))
    }

    /// Enqueue an event for sending.
    #[napi]
    pub fn publish_event(&mut self, topic: String, event: Event) -> napi::Result<()> {
        self.0.publish_event(topic, event.try_into()?);
        Ok(())
    }

    /// Get the next incoming event.
    pub fn receive_event(&mut self) -> napi::Result<Option<(String, Event)>> {
        let Some((topic, event)) = self
            .0
            .receive_event()
            .map_err(|e| Error::ReceiveFailed(format!("failed to receive event: {e}")))?
        else {
            return Ok(None);
        };

        Ok(Some((topic, event.try_into()?)))
    }
}
