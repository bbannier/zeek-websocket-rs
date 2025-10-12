use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use ipnetwork::IpNetwork;
use ordered_float::OrderedFloat;
use pyo3::{
    IntoPyObjectExt,
    exceptions::{PyRuntimeError, PyTypeError},
    intern,
    prelude::*,
    types::{PyBytes, PyDict, PyNone, PyTuple, PyType},
};
use zeek_websocket_types::{TableEntry, Value as RustValue};

#[pyfunction]
fn make_value(data: Value) -> Value {
    data
}

#[derive(Debug, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
#[pyclass(skip_from_py_object, eq, frozen, hash)]
enum Value {
    // NOTE: Ideally we would implement these automatically, but this currently has some issue, see
    // https://github.com/PyO3/pyo3/issues/5510. For now we need to implement `FromPyObject` by
    // hand and keep it in sync with the enum here.
    Boolean(bool),
    Count(u64),
    Integer(i64),
    Real(OrderedFloat<f64>),
    Timespan(chrono::Duration),
    Timestamp(chrono::NaiveDateTime),
    Address(IpAddr),
    Subnet(IpAddr, u8),
    Port(u16, Protocol),
    Vector(Vec<Value>),
    Set(BTreeSet<Value>),
    Table(BTreeMap<Value, Value>),
    Record(BTreeMap<String, Value>),
    // Declare this after other variants so it is tried later in generated conversions from Python
    // values. This allows e.g., `127.0.0.1` to be parsed as an ipaddress first.
    String(String),
    // This can never be converted to automatically since above `String` variant would match first.
    Enum(String),
    None_(),
}

impl<'a, 'py> FromPyObject<'a, 'py> for Value {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        #[allow(clippy::same_functions_in_if_condition)]
        Ok(if let Ok(x) = obj.cast::<Self>() {
            x.try_borrow()?.clone()
        } else if let Ok(x) = obj.extract() {
            Value::Boolean(x)
        } else if let Ok(x) = obj.extract() {
            Value::Real(x)
        } else if let Ok(x) = obj.extract() {
            Value::Timespan(x)
        } else if let Ok(x) = obj.extract() {
            Value::Timestamp(x)
        } else if let Ok(x) = obj.extract() {
            Value::Address(x)
        } else if let Ok((ip, prefix)) = obj.extract() {
            Value::Subnet(ip, prefix)
        } else if let Ok((num, proto)) = obj.extract() {
            Value::Port(num, proto)
        } else if let Ok(x) = obj.extract::<Vec<_>>() {
            Value::Vector(x)
        } else if let Ok(x) = obj.extract() {
            Value::Set(x)
        } else if let Ok(x) = obj.extract() {
            Value::Table(x)
        } else if let Ok(x) = obj.extract() {
            Value::String(x)
        } else if let Ok(_x) = obj.extract::<Py<PyNone>>() {
            Value::None_()
        }
        // First check whether we have an instance of an `Enum` class which we can convert to `Enum`.
        else if let Ok(x) = Python::attach(|py| {
            let enum_module = py.import("enum")?;
            let enum_type = enum_module.getattr("Enum")?;
            obj.is_instance(&enum_type)?;
            obj.getattr("name")?.extract()
        }) {
            Value::Enum(x)
        }
        // Any other class value gets converted to a `Record`.
        else if let Ok(x) = {
            obj.getattr_opt("__dict__").and_then(|x| {
                let x = x.ok_or_else(|| {
                    PyRuntimeError::new_err("argument does not have a __dict__ attribute")
                })?;
                let x: &Bound<PyDict> = x.cast()?;
                let x: PyResult<_> = x
                    .into_iter()
                    .map(|(k, v)| {
                        let k: String = k.extract()?;
                        let v: Value = v.extract()?;
                        Ok((k, v))
                    })
                    .collect();
                x
            })
        } {
            Value::Record(x)
        } else {
            Err(PyTypeError::new_err(format!(
                "automatic conversion of {obj:?} to Value is unsupported"
            )))?
        })
    }
}

#[pymethods]
impl Value {
    fn __repr__(&self) -> String {
        format!("{self:?}")
    }

    fn serialize_json(&self) -> PyResult<String> {
        let value = RustValue::try_from(self.clone())?;
        serde_json::to_string(&value)
            .map_err(|e| PyRuntimeError::new_err(format!("cannot serialize value: {e:?}")))
    }

    #[staticmethod]
    fn deserialize_json(data: &str) -> PyResult<Value> {
        let value: RustValue = serde_json::from_str(data)
            .map_err(|e| PyRuntimeError::new_err(format!("cannot deserialize value: {e:?}")))?;

        Ok(value.into())
    }

    #[allow(clippy::needless_pass_by_value)]
    fn as_record(&self, py: Python, target_type: Py<PyType>) -> PyResult<Option<Py<PyAny>>> {
        let dataclasses = py.import("dataclasses")?;
        let is_dataclass_fn = dataclasses.getattr(intern!(py, "is_dataclass"))?;

        let is_dataclass: bool = is_dataclass_fn
            .call1(PyTuple::new(py, [&target_type])?)?
            .extract()?;

        if !is_dataclass {
            return Err(PyRuntimeError::new_err(format!(
                "{target_type} is not a dataclass"
            )));
        }

        let fields: PyResult<Vec<_>> = match self {
            Value::Vector(values) => values.iter().map(|x| x.value(py)).collect(),
            Value::Record(fields) => fields.values().map(|x| x.value(py)).collect(),
            _ => return Ok(None),
        };

        return Ok(Some(target_type.call(
            py,
            PyTuple::new(py, fields?)?,
            None,
        )?));
    }

    #[allow(clippy::needless_pass_by_value)]
    fn as_enum(&self, py: Python, target_type: Py<PyType>) -> PyResult<Option<Py<PyAny>>> {
        if let Value::Enum(name) = self {
            Ok(Some(target_type.call_method1(
                py,
                "__getitem__",
                PyTuple::new(py, [name.into_py_any(py)?])?,
            )?))
        } else {
            Ok(None)
        }
    }

    #[getter]
    fn value(&self, py: Python) -> PyResult<Py<PyAny>> {
        Ok(match self {
            Value::Boolean(x) => x.into_py_any(py)?,
            Value::Count(x) => x.into_py_any(py)?,
            Value::Integer(x) => x.into_py_any(py)?,
            Value::Real(x) => x.into_py_any(py)?,
            Value::String(x) | Value::Enum(x) => x.into_py_any(py)?,
            Value::Address(x) => x.into_py_any(py)?,
            Value::Subnet(addr, prefix) => {
                (addr.into_py_any(py)?, prefix.into_py_any(py)?).into_py_any(py)?
            }
            Value::Port(num, proto) => {
                (num.into_py_any(py)?, proto.into_py_any(py)?).into_py_any(py)?
            }
            Value::Timespan(x) => x.into_py_any(py)?,
            Value::Timestamp(x) => x.into_py_any(py)?,
            Value::Vector(x) => x.clone().into_py_any(py)?,
            Value::Set(x) => x.clone().into_py_any(py)?,
            Value::Table(x) => x.clone().into_py_any(py)?,
            Value::Record(x) => x.clone().into_py_any(py)?,
            Value::None_() => ().into_py_any(py)?,
        })
    }
}

impl TryFrom<Value> for RustValue {
    type Error = PyErr;

    fn try_from(value: Value) -> PyResult<Self> {
        let value = match value {
            Value::Boolean(x) => RustValue::Boolean(x),
            Value::Count(x) => RustValue::Count(x),
            Value::Integer(x) => RustValue::Integer(x),
            Value::Real(x) => RustValue::Real(x.into_inner()),
            Value::Timespan(x) => RustValue::Timespan(x),
            Value::Timestamp(x) => RustValue::Timestamp(x),
            Value::String(x) => RustValue::String(x),
            Value::Vector(xs) => {
                let xs: PyResult<_> = xs.into_iter().map(RustValue::try_from).collect();
                RustValue::Vector(xs?)
            }
            Value::Set(xs) => {
                let xs: PyResult<_> = xs.into_iter().map(RustValue::try_from).collect();
                RustValue::Set(xs?)
            }
            Value::Table(xs) => {
                let xs: PyResult<_> = xs
                    .into_iter()
                    .map(|(k, v)| Ok(TableEntry::new(k.try_into()?, v.try_into()?)))
                    .collect();
                RustValue::Table(xs?)
            }
            Value::Record(xs) => {
                let xs: PyResult<_> = xs.into_values().map(RustValue::try_from).collect();
                RustValue::Vector(xs?)
            }
            Value::Address(x) => RustValue::Address(x),
            Value::Port(n, p) => RustValue::Port(zeek_websocket_types::Port::new(n, p.into())),
            Value::Subnet(addr, prefix) => RustValue::Subnet(
                IpNetwork::new(addr, prefix)
                    .map_err(|err| PyRuntimeError::new_err(err.to_string()))?,
            ),
            Value::Enum(x) => RustValue::EnumValue(x),
            Value::None_() => RustValue::None,
        };

        Ok(value)
    }
}

impl From<RustValue> for Value {
    fn from(value: RustValue) -> Self {
        match value {
            RustValue::Boolean(x) => Value::Boolean(x),
            RustValue::Count(x) => Value::Count(x),
            RustValue::Integer(x) => Value::Integer(x),
            RustValue::Real(x) => Value::Real(x.into()),
            RustValue::String(x) => Value::String(x),
            RustValue::EnumValue(x) => Value::Enum(x),
            RustValue::Timespan(x) => Value::Timespan(x),
            RustValue::Timestamp(x) => Value::Timestamp(x),
            RustValue::Address(x) => Value::Address(x),
            RustValue::Subnet(x) => Value::Subnet(x.ip(), x.prefix()),
            RustValue::Port(x) => Value::Port(
                x.number(),
                match x.protocol() {
                    zeek_websocket_types::Protocol::TCP => Protocol::TCP,
                    zeek_websocket_types::Protocol::UDP => Protocol::UDP,
                    zeek_websocket_types::Protocol::ICMP => Protocol::ICMP,
                    zeek_websocket_types::Protocol::UNKNOWN => Protocol::UNKNOWN,
                },
            ),
            RustValue::Vector(xs) => Value::Vector(xs.into_iter().map(Into::into).collect()),
            RustValue::Set(xs) => Value::Set(xs.into_iter().map(Into::into).collect()),
            RustValue::Table(xs) => Value::Table(
                xs.into_iter()
                    .map(|TableEntry { key, value }| (key.into(), value.into()))
                    .collect(),
            ),
            #[allow(clippy::redundant_closure_for_method_calls)]
            RustValue::None => Value::None_(),
        }
    }
}

#[pyclass(eq)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum Protocol {
    #[allow(clippy::upper_case_acronyms)]
    UNKNOWN = 1,
    #[allow(clippy::upper_case_acronyms)]
    TCP = 2,
    #[allow(clippy::upper_case_acronyms)]
    UDP = 3,
    #[allow(clippy::upper_case_acronyms)]
    ICMP = 4,
}

impl From<Protocol> for zeek_websocket_types::Protocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::UNKNOWN => zeek_websocket_types::Protocol::UNKNOWN,
            Protocol::TCP => zeek_websocket_types::Protocol::TCP,
            Protocol::UDP => zeek_websocket_types::Protocol::UDP,
            Protocol::ICMP => zeek_websocket_types::Protocol::ICMP,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[pyclass(eq, frozen)]
struct Event(zeek_websocket_types::Event);

#[pymethods]
impl Event {
    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    #[new]
    fn new(name: String, args: Vec<Value>, metadata: Vec<Value>) -> PyResult<Self> {
        let args: PyResult<Vec<_>> = args.into_iter().map(RustValue::try_from).collect();
        let metadata: PyResult<Vec<_>> = metadata.into_iter().map(RustValue::try_from).collect();
        Ok(Self(
            zeek_websocket_types::Event::new(name, args?).with_metadata(metadata?),
        ))
    }

    #[getter(name)]
    fn name(&self) -> &str {
        &self.0.name
    }

    #[getter(args)]
    fn args(&self) -> PyResult<Vec<Value>> {
        let xs: Result<_, _> = self.0.args.iter().cloned().map(Value::try_from).collect();
        Ok(xs?)
    }

    #[getter(metadata)]
    fn metadata(&self) -> PyResult<Vec<Value>> {
        let xs: Result<_, _> = self
            .0
            .metadata
            .iter()
            .cloned()
            .map(Value::try_from)
            .collect();
        Ok(xs?)
    }

    fn serialize_json(&self) -> PyResult<String> {
        serde_json::to_string(&zeek_websocket_types::Data::from(self.0.clone()))
            .map_err(|e| PyRuntimeError::new_err(format!("cannot serialize event: {e:?}")))
    }

    #[staticmethod]
    fn deserialize_json(data: &str) -> PyResult<Event> {
        let value: zeek_websocket_types::Data = serde_json::from_str(data)
            .map_err(|e| PyRuntimeError::new_err(format!("cannot deserialize event: {e:?}")))?;

        match value {
            zeek_websocket_types::Data::Event(e) => Ok(Self(e)),
            zeek_websocket_types::Data::Other(other) => Err(PyRuntimeError::new_err(format!(
                "cannot interpret received data '{other:?}' as event"
            ))),
        }
    }
}

#[pyclass]
struct ProtocolBinding(crate::protocol::Binding);

#[pymethods]
impl ProtocolBinding {
    #[new]
    fn new(subscriptions: Vec<String>) -> Self {
        Self(crate::protocol::Binding::new(subscriptions))
    }

    fn handle_incoming(&mut self, data: &Bound<PyBytes>) -> PyResult<()> {
        let message = serde_json::from_slice(data.as_bytes())
            .map_err(|e| PyRuntimeError::new_err(format!("data payload not understood: {e}")))?;

        self.0
            .handle_incoming(message)
            .map_err(|e| PyRuntimeError::new_err(format!("failed to handle message: {e}")))
    }

    fn outgoing<'py>(&mut self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.outgoing().map(|x| PyBytes::new(py, &x))
    }

    fn publish_event(&mut self, topic: &str, event: Event) {
        self.0.publish_event(topic, event.0);
    }

    fn receive_event(&mut self) -> PyResult<Option<(String, Event)>> {
        Ok(self
            .0
            .receive_event()
            .map_err(|e| PyRuntimeError::new_err(format!("failed to receive event: {e}")))?
            .map(|(topic, event)| (topic, Event(event))))
    }
}

#[pymodule]
mod zeek_websocket {
    #[pymodule_export]
    use super::{Event, Protocol, ProtocolBinding, Value, make_value};
}
