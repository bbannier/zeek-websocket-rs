use if_chain::if_chain;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::Display,
    net::IpAddr,
    str::FromStr,
};
use thiserror::Error;

#[doc(no_inline)]
pub use chrono::TimeDelta;
#[doc(no_inline)]
pub use ipnetwork::IpNetwork;
#[doc(no_inline)]
pub use iso8601::DateTime;

/// Enum for all basic types understood by Zeek's WebSocket API.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "@data-type", rename_all = "lowercase", content = "data")]
pub enum Value {
    None,
    Boolean(bool),
    Count(u64),
    Integer(i64),
    Real(f64),
    #[serde(with = "timespan")]
    Timespan(TimeDelta),
    Timestamp(DateTime),
    String(String),
    #[serde(rename = "enum-value")]
    EnumValue(String),
    Address(IpAddr),
    Subnet(IpNetwork),
    Port(Port),
    Vector(Vec<Value>),
    Set(Vec<Value>),
    Table(Vec<TableEntry>),
}

macro_rules! impl_from_T {
    ($t:ty, $c:path) => {
        impl From<$t> for Value {
            fn from(value: $t) -> Self {
                $c(value.into())
            }
        }
    };
}

macro_rules! impl_T {
    ($t:ty, $c:path) => {
        impl_from_T!($t, $c);

        impl TryFrom<Value> for $t {
            type Error = ConversionError;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                let $c(x) = value else {
                    return Err(ConversionError::MismatchedTypes);
                };

                x.try_into()
                    .map_err(|e| ConversionError::Domain(Box::new(e)))
            }
        }
    };
}

impl_T!(bool, Value::Boolean);
impl_T!(u64, Value::Count);
impl_T!(u32, Value::Count);
impl_T!(u16, Value::Count);
impl_T!(u8, Value::Count);
impl_T!(i64, Value::Integer);
impl_T!(i32, Value::Integer);
impl_T!(i16, Value::Integer);
impl_T!(i8, Value::Integer);
impl_T!(f64, Value::Real);
impl_from_T!(f32, Value::Real);
impl_T!(TimeDelta, Value::Timespan);
impl_T!(DateTime, Value::Timestamp);
impl_T!(String, Value::String);
impl_from_T!(&str, Value::String);
impl_T!(IpAddr, Value::Address);
impl_T!(IpNetwork, Value::Subnet);
impl_T!(Port, Value::Port);

impl From<()> for Value {
    #[allow(clippy::ignored_unit_patterns)]
    fn from(_: ()) -> Self {
        Value::None
    }
}

impl<T> From<Vec<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Vec<T>) -> Self {
        Value::Vector(value.into_iter().map(Into::into).collect())
    }
}

impl<T> From<HashSet<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: HashSet<T>) -> Self {
        Value::Set(value.into_iter().map(Into::into).collect())
    }
}

impl<K, V> From<HashMap<K, V>> for Value
where
    K: Into<Value>,
    V: Into<Value>,
{
    fn from(value: HashMap<K, V>) -> Self {
        Value::Table(value.into_iter().map(Into::into).collect())
    }
}

/// Error enum for Zeek-related deserialization errors.
#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("invalid port '{0}'")]
    InvalidPort(String),

    #[error("invalid port number '{0}'")]
    InvalidPortNumber(String),

    #[error("invalid protocol '{0}'")]
    InvalidProtocol(String),

    #[error("invalid timespan unit '{0}'")]
    InvalidTimespanUnit(String),
}

/// Error enum for Zeek-related serialization errors.
#[derive(Error, Debug, PartialEq)]
pub enum SerializationError {
    #[error("value not representable: {0}")]
    NotRepresentable(String),
}

/// Error enum for errors related to conversions from a Zeek value.
#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("cannot convert value to target type")]
    MismatchedTypes,

    #[error("conversion to target type failed")]
    Domain(Box<dyn Error>),
}

impl PartialEq for ConversionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Not ideal, but just compare stringifications of the errors.
            (Self::Domain(l0), Self::Domain(r0)) => l0.to_string() == r0.to_string(),

            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

/// A Zeek port which holds both a port number and a protocol identifier.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Port {
    number: u16,
    protocol: Protocol,
}

impl Port {
    #[must_use]
    pub fn new(number: u16, protocol: Protocol) -> Self {
        Self { number, protocol }
    }

    #[must_use]
    pub fn number(&self) -> u16 {
        self.number
    }

    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl<'de> serde::Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        Port::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Port {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.number;
        let p = self.protocol;
        f.write_str(&format!("{n}/{p}"))
    }
}

impl FromStr for Port {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (number, proto) = s
            .split_once('/')
            .ok_or_else(|| ParseError::InvalidPort(s.to_string()))?;
        Ok(Self {
            number: number
                .parse()
                .map_err(|_| ParseError::InvalidPortNumber(number.to_string()))?,
            protocol: proto.parse()?,
        })
    }
}

/// A network protocol understood by Zeek.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

mod timespan {
    #![allow(clippy::missing_errors_doc)]

    use super::{ParseError, SerializationError};
    use chrono::TimeDelta;
    use serde::{Deserialize, de, ser::Error};
    use std::str::FromStr;

    enum Unit {
        NS,
        MS,
        S,
        Min,
        H,
        D,
    }

    impl FromStr for Unit {
        type Err = ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(match s {
                "ns" => Self::NS,
                "ms" => Self::MS,
                "s" => Self::S,
                "min" => Self::Min,
                "h" => Self::H,
                "d" => Self::D,
                _ => Err(ParseError::InvalidTimespanUnit(s.to_string()))?,
            })
        }
    }

    pub fn serialize<S>(duration: &TimeDelta, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // If we only store seconds format as a seconds value.
        if duration.subsec_nanos() == 0 {
            return serializer.serialize_str(&format!("{}s", duration.num_seconds()));
        }

        // We have nanoseconds. Since a `timespace` can only represent integer values we must
        // represent the duration as an `i64` of nanos. Should the number of nanos exceed the range
        // of `i64` the value is not representable.
        let num_nanos = duration.num_nanoseconds().ok_or_else(|| {
            S::Error::custom(SerializationError::NotRepresentable(format!(
                "'{duration}' needs nanosecond accuracy but exceeds its range"
            )))
        })?;
        serializer.serialize_str(&format!("{num_nanos}ns"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TimeDelta, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;

        let unit_start = s
            .chars()
            .enumerate()
            .find_map(|(i, c)| {
                if c != '-' && !c.is_ascii_digit() {
                    Some(i)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let num = s[0..unit_start].parse().map_err(de::Error::custom)?;

        let unit = &s[unit_start..];
        let unit: Unit = unit
            .parse()
            .map_err(|_| de::Error::custom(ParseError::InvalidTimespanUnit(unit.into())))?;

        Ok(match unit {
            Unit::NS => TimeDelta::nanoseconds(num),
            Unit::MS => TimeDelta::milliseconds(num),
            Unit::S => TimeDelta::seconds(num),
            Unit::Min => TimeDelta::minutes(num),
            Unit::H => TimeDelta::hours(num),
            Unit::D => TimeDelta::days(num),
        })
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
            Self::ICMP => "icmp",
            Self::UNKNOWN => "unknown",
        })
    }
}

impl FromStr for Protocol {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Self::TCP,
            "udp" => Self::UDP,
            "icmp" => Self::ICMP,
            "unknown" => Self::UNKNOWN,
            _ => Err(ParseError::InvalidProtocol(s.to_string()))?,
        })
    }
}

/// An entry in a table in a [`Value::Table`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TableEntry {
    key: Value,
    value: Value,
}

impl TableEntry {
    #[must_use]
    pub fn new(key: Value, value: Value) -> Self {
        TableEntry { key, value }
    }

    #[must_use]
    pub fn key(&self) -> &Value {
        &self.key
    }

    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl<K, V> From<(K, V)> for TableEntry
where
    K: Into<Value>,
    V: Into<Value>,
{
    fn from((key, value): (K, V)) -> Self {
        TableEntry::new(key.into(), value.into())
    }
}

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

impl Message {
    pub fn new_data<T, D>(topic: T, data: D) -> Self
    where
        T: Into<String>,
        D: Into<Data>,
    {
        Message::DataMessage {
            topic: topic.into(),
            data: data.into(),
        }
    }
}

#[cfg(feature = "tungstenite")]
impl From<Message> for tungstenite::Message {
    fn from(value: Message) -> Self {
        let msg = serde_json::to_string(&value).expect("conversion should never fail");
        msg.into()
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

impl From<Event> for Data {
    fn from(value: Event) -> Self {
        Data::Event(value)
    }
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

                return Data::Event(Event::new(name, args).with_metadata(metadata));
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

impl Event {
    pub fn new<N, A>(name: N, args: Vec<A>) -> Self
    where
        N: Into<String>,
        A: Into<Value>,
    {
        Self {
            name: name.into(),
            args: args.into_iter().map(Into::into).collect(),
            metadata: Vec::default(),
        }
    }

    #[must_use]
    pub fn with_metadata<M>(mut self, metadata: Vec<M>) -> Self
    where
        M: Into<Value>,
    {
        self.metadata = metadata.into_iter().map(Into::into).collect();
        self
    }
}

/// Topics to subscribe to. This should be the first message sent to the server.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
pub struct Subscriptions(pub Vec<String>);

impl<T> From<Vec<T>> for Subscriptions
where
    T: ToString,
{
    fn from(value: Vec<T>) -> Self {
        Subscriptions(value.iter().map(ToString::to_string).collect())
    }
}

impl<T> From<&[T]> for Subscriptions
where
    T: ToString,
{
    fn from(value: &[T]) -> Self {
        Subscriptions(value.iter().map(ToString::to_string).collect())
    }
}

impl<T, const N: usize> From<&[T; N]> for Subscriptions
where
    T: ToString,
{
    fn from(value: &[T; N]) -> Self {
        Subscriptions(value.iter().map(ToString::to_string).collect())
    }
}

impl std::fmt::Display for Subscriptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[{}]", self.0.join(", ")))
    }
}

#[cfg(feature = "tungstenite")]
impl From<Subscriptions> for tungstenite::Message {
    fn from(value: Subscriptions) -> Self {
        let msg = serde_json::to_string(&value).expect("conversion should never fail");
        msg.into()
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

    use std::{i64, net::IpAddr, str::FromStr};

    use crate::{
        ConversionError, Data, Event, Message, ParseError, Port, Protocol, Subscriptions,
        TableEntry, Value,
    };
    use chrono::TimeDelta;
    use ipnetwork::IpNetwork;
    use iso8601::DateTime;
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
            Message::new_data("/foo/bar", Event::new("pong", vec![42u64]),),
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
            Message::new_data("/foo/bar", Data::Other(Value::Count(42))),
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
        let event = Message::new_data("my_topic", Event::new("my_event", vec![1]));

        let msg: tungstenite::Message = event.clone().try_into().unwrap();
        let event2: Message = msg.try_into().unwrap();

        assert_eq!(event, event2);
    }

    #[cfg(feature = "tungstenite")]
    #[test]
    fn subscriptions_try_from_into_tungstenite() {
        let subscriptions = Subscriptions::from(&["a", "b"]);

        let msg: tungstenite::Message = subscriptions.clone().try_into().unwrap();
        let subscriptions2: Subscriptions = msg.try_into().unwrap();

        assert_eq!(subscriptions, subscriptions2);
    }

    #[test]
    fn value_from_json() {
        assert_eq!(
            Value::from(()),
            serde_json::from_value(json!({"@data-type": "none"})).unwrap()
        );
        assert_eq!(
            Value::from(true),
            serde_json::from_value(json!({"@data-type": "boolean", "data": true})).unwrap()
        );
        assert_eq!(
            Value::from(123u64),
            serde_json::from_value(json!({"@data-type": "count", "data": 123})).unwrap()
        );
        assert_eq!(
            Value::from(-7),
            serde_json::from_value(json!({"@data-type": "integer", "data": -7})).unwrap()
        );
        assert_eq!(
            Value::from(7.5),
            serde_json::from_value(json!({"@data-type": "real", "data": 7.5})).unwrap()
        );
        assert_eq!(
            Value::from(TimeDelta::milliseconds(1500)),
            serde_json::from_value(json!({"@data-type": "timespan", "data": "1500ms"})).unwrap()
        );
        assert_eq!(
            Value::from("2022-04-10T07:00:00.000".parse::<DateTime>().unwrap()),
            serde_json::from_value(
                json!({"@data-type": "timestamp", "data": "2022-04-10T07:00:00.000"})
            )
            .unwrap()
        );
        assert_eq!(
            Value::from("Hello World!"),
            serde_json::from_value(json!({"@data-type": "string", "data": "Hello World!"}))
                .unwrap()
        );
        assert_eq!(
            Value::EnumValue("foo".into()),
            serde_json::from_value(json!({"@data-type": "enum-value", "data": "foo"})).unwrap()
        );
        assert_eq!(
            Value::from(IpAddr::from_str("2001:db8::").unwrap()),
            serde_json::from_value(json!({"@data-type": "address", "data": "2001:db8::"})).unwrap()
        );
        assert_eq!(
            Value::from(IpNetwork::from_str("255.255.255.0/24").unwrap()),
            serde_json::from_value(json!({"@data-type": "subnet", "data": "255.255.255.0/24"}))
                .unwrap()
        );
        assert_eq!(
            Value::from(Port::from_str("8080/tcp").unwrap()),
            serde_json::from_value(json!({"@data-type": "port", "data": "8080/tcp"})).unwrap()
        );
        assert_eq!(
            Value::from(vec![Value::from(42u8), 23i32.into()]),
            serde_json::from_value(json!({
                "@data-type": "vector",
                "data": [
                  {
                    "@data-type": "count",
                    "data": 42
                  },
                  {
                    "@data-type": "integer",
                    "data": 23
                  }
            ]}))
            .unwrap()
        );
        assert_eq!(
            Value::Set(vec!["foo".into(), "bar".into()]),
            serde_json::from_value(json!({
                "@data-type": "set",
                "data": [
                  {
                    "@data-type": "string",
                    "data": "foo"
                  },
                  {
                    "@data-type": "string",
                    "data": "bar"
                  }
            ]}))
            .unwrap()
        );
        assert_eq!(
            Value::Table(vec![
                ("first-name", "John").into(),
                ("last-name", "Doe").into()
            ]),
            serde_json::from_value(json!({
               "@data-type": "table",
               "data": [
                 {
                   "key": {
                     "@data-type": "string",
                     "data": "first-name"
                   },
                   "value": {
                     "@data-type": "string",
                     "data": "John"
                   }
                 },
                 {
                   "key": {
                     "@data-type": "string",
                     "data": "last-name"
                   },
                   "value": {
                     "@data-type": "string",
                     "data": "Doe"
                   }
                 }
               ]
            }))
            .unwrap()
        );
    }

    #[test]
    fn try_into() {
        assert_eq!(Value::from(true).try_into(), Ok(true));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u64));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u32));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u16));
        assert_eq!(Value::from(0u64).try_into(), Ok(0u8));
        assert_eq!(Value::from(0).try_into(), Ok(0i64));
        assert_eq!(Value::from(0).try_into(), Ok(0i32));
        assert_eq!(Value::from(0).try_into(), Ok(0i16));
        assert_eq!(Value::from(0).try_into(), Ok(0i8));
        assert_eq!(Value::from(0.).try_into(), Ok(0.));

        assert_eq!(
            Value::from(TimeDelta::seconds(1)).try_into(),
            Ok(TimeDelta::seconds(1))
        );
        assert_eq!(
            Value::from(DateTime::default()).try_into(),
            Ok(DateTime::default())
        );

        let addr = IpAddr::from_str("::0").unwrap();
        assert_eq!(Value::from(addr).try_into(), Ok(addr));

        let network = IpNetwork::new(addr, 8).unwrap();
        assert_eq!(Value::from(network).try_into(), Ok(network));

        let port = Port::new(42, Protocol::TCP);
        assert_eq!(Value::from(port).try_into(), Ok(port));

        let not_string: Result<String, _> = Value::from(0).try_into();
        assert_eq!(not_string, Err(ConversionError::MismatchedTypes));

        let outside_range: Result<i8, _> = Value::from(i64::MAX).try_into();
        assert!(matches!(outside_range, Err(ConversionError::Domain(_))));
    }

    #[test]
    fn port() {
        let p = Port::new(8080, Protocol::TCP);
        assert_eq!(p.number(), 8080);
        assert_eq!(p.protocol(), Protocol::TCP);

        assert_eq!(serde_json::to_string(&p).unwrap(), r#""8080/tcp""#);
        assert_eq!(p, "8080/tcp".parse().unwrap());

        assert_eq!(
            Err(ParseError::InvalidPort("foo".into())),
            "foo".parse::<Port>()
        );
        assert_eq!(
            Err(ParseError::InvalidPortNumber("1234567890".into())),
            "1234567890/tcp".parse::<Port>()
        );
    }

    #[test]
    fn protocol() {
        assert_eq!(Protocol::from_str("tcp"), Ok(Protocol::TCP));
        assert_eq!(Protocol::from_str("udp"), Ok(Protocol::UDP));
        assert_eq!(Protocol::from_str("icmp"), Ok(Protocol::ICMP));
        assert_eq!(Protocol::from_str("unknown"), Ok(Protocol::UNKNOWN));
        assert_eq!(
            Protocol::from_str("foo"),
            Err(ParseError::InvalidProtocol("foo".into()))
        );

        assert_eq!(Protocol::TCP.to_string(), "tcp");
        assert_eq!(Protocol::UDP.to_string(), "udp");
        assert_eq!(Protocol::ICMP.to_string(), "icmp");
        assert_eq!(Protocol::UNKNOWN.to_string(), "unknown");
    }

    #[test]
    fn table() {
        assert_eq!(
            serde_json::from_value::<Value>(json!({"@data-type":"table", "data": []})).unwrap(),
            Value::Table(vec![])
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({
            "@data-type":"table",
            "data": [{
                "key":{
                    "@data-type":"string",
                    "data": "one",
                },
                "value":{
                    "@data-type":"count",
                    "data": 1,
                }
            }]}))
            .unwrap(),
            Value::Table(vec![("one", 1u8).into()])
        );

        let t = TableEntry::new("one".into(), 1u8.into());
        assert_eq!(t.key().clone(), Value::String("one".into()));
        assert_eq!(t.value().clone(), Value::Count(1));
    }

    #[test]
    fn timespan() {
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1ns" }))
                .unwrap(),
            Value::from(TimeDelta::nanoseconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1ms" }))
                .unwrap(),
            Value::from(TimeDelta::milliseconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1s" }))
                .unwrap(),
            Value::from(TimeDelta::seconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1min" }))
                .unwrap(),
            Value::from(TimeDelta::minutes(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1h" }))
                .unwrap(),
            Value::from(TimeDelta::hours(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1d" }))
                .unwrap(),
            Value::from(TimeDelta::days(1))
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "-42s" }))
                .unwrap(),
            Value::from(TimeDelta::seconds(-42))
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1us" }))
                .err()
                .unwrap()
                .to_string(),
            r"invalid timespan unit 'us'"
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "-1-1s" }))
                .err()
                .unwrap()
                .to_string(),
            r"invalid digit found in string"
        );

        assert_eq!(
            serde_json::to_string(&Value::from(TimeDelta::nanoseconds(12))).unwrap(),
            serde_json::to_string(&json!({"@data-type": "timespan", "data": "12ns"})).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Value::from(TimeDelta::seconds(12))).unwrap(),
            serde_json::to_string(&json!({"@data-type": "timespan", "data": "12s"})).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Value::from(
                TimeDelta::weeks(52 * 100_000_000) + TimeDelta::nanoseconds(1)
            ))
            .err()
            .unwrap()
            .to_string(),
            "value not representable: 'PT3144960000000000.000000001S' needs nanosecond accuracy but exceeds its range"
        );
    }
}
