#![doc = include_str!("../README.md")]

//! ## Feature flags
#![doc = document_features::document_features!()]

use crate::types::Value;
use if_chain::if_chain;
use serde::{Deserialize, Serialize};

#[cfg(feature = "tungstenite")]
use thiserror::Error;

pub mod types;

/// Data messages of the Zeek API.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Message {
    /// An ACK message typically sent by the server on successful subscription.
    Ack {
        /// Endpoint ID assigned by the server for this client.
        endpoint: String,
        /// Zeek version of the server.
        version: String,
    },

    /// An error sent by the server.
    Error {
        /// Zeek-assigned kind of the error.
        code: String,
        /// Additional context.
        context: String,
    },

    /// Message received over a topic.
    #[serde(rename = "data-message")]
    DataMessage {
        /// Topic of the message.
        topic: String,

        /// Data payload of the message.
        #[serde(flatten)]
        data: Data,
    },
}

#[cfg(feature = "tungstenite")]
impl TryInto<tungstenite::Message> for Message {
    type Error = serde_json::Error;

    fn try_into(
        self,
    ) -> Result<tungstenite::Message, <Message as TryInto<tungstenite::Message>>::Error> {
        let msg = serde_json::to_string(&self)?;
        Ok(msg.into())
    }
}

#[cfg(feature = "tungstenite")]
/// Error enum for Zeek-related deserialization errors.
#[derive(Error, Debug, PartialEq)]
pub enum DeserializationError {
    #[error("unexpected message type")]
    UnexpectedMessageType,

    #[error("could not parse message JSON: {0}")]
    Json(String),
}

#[cfg(feature = "tungstenite")]
impl TryFrom<tungstenite::Message> for Message {
    type Error = DeserializationError;

    fn try_from(
        value: tungstenite::Message,
    ) -> Result<Self, <Message as TryFrom<tungstenite::Message>>::Error> {
        let msg = match value {
            tungstenite::Message::Text(txt) => serde_json::from_str(&txt),
            tungstenite::Message::Binary(bin) => serde_json::from_slice(&bin),
            _ => return Err(DeserializationError::UnexpectedMessageType),
        }
        .map_err(|e| DeserializationError::Json(e.to_string()))?;

        Ok(msg)
    }
}

/// Data payload of a Zeek API message.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(from = "Value", into = "Value")]
pub enum Data {
    /// A Zeek event.
    Event(Event),

    /// Anything else.
    Other(Value),
}

const EVENT_TYPE: u64 = 1;
const FORMAT_NR: u64 = 1;

impl From<Value> for Data {
    fn from(value: Value) -> Self {
        if_chain! {
            if let Value::Vector(xs) = &value;
            if let Some(Value::Count(EVENT_TYPE)) = xs.get(1); // Events have type `1`.

            if let Some(Value::Vector(data)) = xs.get(2);
            if let Some(Value::String(name)) = data.first().cloned();
            if let Some(Value::Vector(args)) = data.get(1).cloned();

            then {
                // Metadata might be present or not. Currently nodes seem to send it, but it is
                // undocumented.
                let metadata = match data.get(2) {
                    Some(Value::Vector(xs)) => xs.clone(),
                    Some(xs) => vec![xs.clone()],
                    None => vec![],
                };

                return Data::Event(Event { name, args, metadata });
            }
        };

        Data::Other(value)
    }
}

impl From<Data> for Value {
    fn from(val: Data) -> Self {
        match val {
            Data::Event(event) => {
                let data = vec![
                    Value::String(event.name),
                    Value::Vector(event.args),
                    Value::Vector(event.metadata),
                ];

                Value::Vector(vec![
                    Value::Count(FORMAT_NR),
                    Value::Count(EVENT_TYPE),
                    Value::Vector(data),
                ])
            }

            Data::Other(data) => data,
        }
    }
}

/// A Zeek event.
#[derive(Debug, PartialEq, Clone)]
pub struct Event {
    /// Name of the event.
    pub name: String,

    /// Arguments of the event.
    pub args: Vec<Value>,

    /// Event metadata.
    pub metadata: Vec<Value>,
}

/// Topics to subscribe to. This should be the first message sent to the server.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct Subscriptions(pub Vec<String>);

#[cfg(feature = "tungstenite")]
impl TryInto<tungstenite::Message> for Subscriptions {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<tungstenite::Message, Self::Error> {
        let msg = serde_json::to_string(&self)?;
        Ok(msg.into())
    }
}

#[cfg(feature = "tungstenite")]
impl TryFrom<tungstenite::Message> for Subscriptions {
    type Error = DeserializationError;

    fn try_from(value: tungstenite::Message) -> Result<Self, Self::Error> {
        let msg = match value {
            tungstenite::Message::Text(txt) => serde_json::from_str(&txt),
            tungstenite::Message::Binary(bin) => serde_json::from_slice(&bin),
            _ => return Err(DeserializationError::UnexpectedMessageType),
        }
        .map_err(|e| DeserializationError::Json(e.to_string()))?;

        Ok(msg)
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use crate::{
        types::Value,
        {Data, Event, Message},
    };
    use serde_json::json;

    #[test]
    fn from_json() -> Result<(), serde_json::Error> {
        assert_eq!(
            Message::Ack {
                endpoint: "925c9110-5b87-57d9-9d80-b65568e87a44".into(),
                version: "2.2.0-22".into()
            },
            serde_json::from_value(json!({
              "type": "ack",
              "endpoint": "925c9110-5b87-57d9-9d80-b65568e87a44",
              "version": "2.2.0-22"
            }))?
        );

        assert_eq!(
            Message::Error {
                code: "deserialization_failed".into(),
                context: "input #1 contained malformed JSON".into()
            },
            serde_json::from_value(json!({
              "type": "error",
              "code": "deserialization_failed",
              "context": "input #1 contained malformed JSON"
            }))?
        );

        assert_eq!(
            Message::DataMessage {
                topic: "/foo/bar".into(),
                data: Data::Event(Event {
                    name: "pong".into(),
                    args: vec![Value::Count(42)],
                    metadata: vec![],
                }),
            },
            serde_json::from_value(json!({
                "type": "data-message",
                "topic": "/foo/bar",
                "@data-type": "vector",
                "data": [
                    {"@data-type": "count", "data": 1},
                    {"@data-type": "count", "data": 1},
                    {"@data-type": "vector", "data": [
                        {"@data-type": "string", "data": "pong"},
                        {"@data-type": "vector", "data": [
                            {"@data-type": "count", "data": 42}]
                        }]
                    },
                ]
            }))?
        );

        assert_eq!(
            Message::DataMessage {
                topic: "/foo/bar".into(),
                data: Data::Other(Value::Count(42)),
            },
            serde_json::from_value(json!({
                "type": "data-message",
                "topic": "/foo/bar",
                "@data-type": "count",
                "data": 42
            }))?
        );

        Ok(())
    }

    #[cfg(feature = "tungstenite")]
    #[test]
    fn message_try_from_into_tungstenite() {
        let event = Message::DataMessage {
            topic: "my_topic".into(),
            data: Data::Event(Event {
                name: "my_event".into(),
                args: vec![],
                metadata: vec![],
            }),
        };

        let msg: tungstenite::Message = event.clone().try_into().unwrap();
        let event2: Message = msg.try_into().unwrap();

        assert_eq!(event, event2);
    }

    #[cfg(feature = "tungstenite")]
    #[test]
    fn subscriptions_try_from_into_tungstenite() {
        use crate::Subscriptions;

        let subscriptions = Subscriptions(vec!["a".into(), "b".into()]);

        let msg: tungstenite::Message = subscriptions.clone().try_into().unwrap();
        let subscriptions2: Subscriptions = msg.try_into().unwrap();

        assert_eq!(subscriptions, subscriptions2);
    }
}
