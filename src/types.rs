//! # Basic types of Zeek's WebSocket API
//!
//! The main type of this module is [`Value`] which holds values of the Zeek API. Use its enum
//! variants to create values of specific types, e.g.,
//!
//! ```
//! # use zeek_websocket::types::Value;
//! let value = Value::Count(4711);
//! ```

use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::IpAddr, str::FromStr};
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

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::{net::IpAddr, str::FromStr};

    use crate::types::{ParseError, Port, Protocol, TableEntry, Value};
    use chrono::TimeDelta;
    use ipnetwork::IpNetwork;
    use serde_json::json;

    #[test]
    fn value_from_json() {
        assert_eq!(
            Value::None,
            serde_json::from_value(json!({"@data-type": "none"})).unwrap()
        );
        assert_eq!(
            Value::Boolean(true),
            serde_json::from_value(json!({"@data-type": "boolean", "data": true})).unwrap()
        );
        assert_eq!(
            Value::Count(123),
            serde_json::from_value(json!({"@data-type": "count", "data": 123})).unwrap()
        );
        assert_eq!(
            Value::Integer(-7),
            serde_json::from_value(json!({"@data-type": "integer", "data": -7})).unwrap()
        );
        assert_eq!(
            Value::Real(7.5),
            serde_json::from_value(json!({"@data-type": "real", "data": 7.5})).unwrap()
        );
        assert_eq!(
            Value::Timespan(TimeDelta::milliseconds(1500)),
            serde_json::from_value(json!({"@data-type": "timespan", "data": "1500ms"})).unwrap()
        );
        assert_eq!(
            Value::Timestamp("2022-04-10T07:00:00.000".parse().unwrap()),
            serde_json::from_value(
                json!({"@data-type": "timestamp", "data": "2022-04-10T07:00:00.000"})
            )
            .unwrap()
        );
        assert_eq!(
            Value::String("Hello World!".into()),
            serde_json::from_value(json!({"@data-type": "string", "data": "Hello World!"}))
                .unwrap()
        );
        assert_eq!(
            Value::EnumValue("foo".into()),
            serde_json::from_value(json!({"@data-type": "enum-value", "data": "foo"})).unwrap()
        );
        assert_eq!(
            Value::Address(IpAddr::from_str("2001:db8::").unwrap()),
            serde_json::from_value(json!({"@data-type": "address", "data": "2001:db8::"})).unwrap()
        );
        assert_eq!(
            Value::Subnet(IpNetwork::from_str("255.255.255.0/24").unwrap()),
            serde_json::from_value(json!({"@data-type": "subnet", "data": "255.255.255.0/24"}))
                .unwrap()
        );
        assert_eq!(
            Value::Port(Port::from_str("8080/tcp").unwrap()),
            serde_json::from_value(json!({"@data-type": "port", "data": "8080/tcp"})).unwrap()
        );
        assert_eq!(
            Value::Vector(vec![Value::Count(42), Value::Integer(23)]),
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
            Value::Set(vec![
                Value::String("foo".into()),
                Value::String("bar".into())
            ]),
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
                TableEntry::new(
                    Value::String("first-name".into()),
                    Value::String("John".into())
                ),
                TableEntry::new(
                    Value::String("last-name".into()),
                    Value::String("Doe".into())
                )
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
    fn port() {
        let p = &Port {
            number: 8080,
            protocol: Protocol::TCP,
        };

        assert_eq!(serde_json::to_string(&p).unwrap(), r#""8080/tcp""#);
        assert_eq!(p, &"8080/tcp".parse().unwrap());

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
    fn timespan() {
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1ns" }))
                .unwrap(),
            Value::Timespan(TimeDelta::nanoseconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1ms" }))
                .unwrap(),
            Value::Timespan(TimeDelta::milliseconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1s" }))
                .unwrap(),
            Value::Timespan(TimeDelta::seconds(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1min" }))
                .unwrap(),
            Value::Timespan(TimeDelta::minutes(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1h" }))
                .unwrap(),
            Value::Timespan(TimeDelta::hours(1))
        );
        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "1d" }))
                .unwrap(),
            Value::Timespan(TimeDelta::days(1))
        );

        assert_eq!(
            serde_json::from_value::<Value>(json!({ "@data-type": "timespan", "data": "-42s" }))
                .unwrap(),
            Value::Timespan(TimeDelta::seconds(-42))
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
            serde_json::to_string(&Value::Timespan(TimeDelta::nanoseconds(12))).unwrap(),
            serde_json::to_string(&json!({"@data-type": "timespan", "data": "12ns"})).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Value::Timespan(TimeDelta::seconds(12))).unwrap(),
            serde_json::to_string(&json!({"@data-type": "timespan", "data": "12s"})).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&Value::Timespan(
                TimeDelta::weeks(52 * 100_000_000) + TimeDelta::nanoseconds(1)
            ))
            .err()
            .unwrap()
            .to_string(),
            "value not representable: 'PT3144960000000000.000000001S' needs nanosecond accuracy but exceeds its range"
        );
    }
}
