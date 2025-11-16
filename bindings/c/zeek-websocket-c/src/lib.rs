use std::{
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    ptr, slice,
    time::Duration,
};

use tokio::{runtime::Runtime, sync::mpsc::error::SendError, task::JoinHandle};
use zeek_websocket::{
    IpNetwork,
    client::{self, Outbox, ServiceConfig, ZeekClient},
    protocol::ProtocolError,
};

pub struct Client {
    rt: Runtime,
    _service: JoinHandle<()>,
    outbox: Option<Outbox>,
}

impl Client {
    /// Create a new client.
    ///
    /// @param app_name name of the client
    /// @param uri Zeek full path to the Zeek endpoint to connect to
    /// @params topics pointer to an array of topics to subscribe to
    /// @params num_topics number of elements in `topics`
    /// @param receive_callback callback to invoke when a new event is received
    /// @param error_callback callback to invoke when an error is encounter
    /// @param config if given the `ClientConfig` to use to deviate from the default
    ///
    /// The returned client must be freed by caller with `zws_client_free`.
    ///
    /// Callbacks might be invoked from another thread and must perform their own synchronization
    /// to be free of races.
    ///
    /// # Safety
    ///
    /// All passed strings must be NULL-terminated and point to valid UTF-8 strings.
    ///
    /// `outbox_size` must either be unset, or point to a non-zero integer.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_client_new(
        app_name: *const libc::c_char,
        uri: *const libc::c_char,
        topics: *const *const libc::c_char,
        num_topics: usize,
        receive_callback: ClientReceiveCallback,
        error_callback: ClientErrorCallback,
        config: Option<&ClientConfig>,
    ) -> Option<Box<Self>> {
        let app_name = unsafe { CStr::from_ptr(app_name) }.to_str().ok()?;

        let topics = unsafe { slice::from_raw_parts(topics, num_topics) };
        let topics: Result<Vec<_>, _> = topics
            .iter()
            .map(|x| unsafe { CStr::from_ptr(*x) }.to_str())
            .collect();
        let Ok(subscriptions) = topics else {
            let error = c"one or more topic names include invalid UTF-8";
            error_callback(ClientError::InvalidTopic, error.as_ptr());

            return None;
        };

        let Ok(uri) = unsafe { CStr::from_ptr(uri) }.to_str() else {
            let error = c"uri cannot contain literal NULL";
            error_callback(ClientError::InvalidUri, error.as_ptr());

            return None;
        };
        let endpoint = match uri.try_into() {
            Ok(x) => x,
            Err(e) => {
                let error = safe_string(&format!("invalid uri: {e}"));
                error_callback(ClientError::InvalidUri, error.as_ptr());

                return None;
            }
        };

        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .build()
        {
            Ok(x) => x,
            Err(e) => {
                let error = safe_string(&format!("could not start background thread: {e}"));
                error_callback(ClientError::Runtime, error.as_ptr());

                return None;
            }
        };

        struct Inner {
            receive_callback: ClientReceiveCallback,
            error_callback: ClientErrorCallback,
        }

        impl ZeekClient for Inner {
            async fn event(&mut self, topic: String, event: zeek_websocket::Event) {
                let topic = safe_string(&topic);
                (self.receive_callback)(topic.as_ptr(), &Event(event));
            }

            async fn error(&mut self, error: ProtocolError) {
                let code = (&error).into();
                let context = safe_string(&error.to_string());
                (self.error_callback)(code, context.as_ptr());
            }

            async fn connected(&mut self, _ack: zeek_websocket::Message) {
                // Nothing.
            }
        }

        let config = config.cloned().map(ServiceConfig::from).unwrap_or_default();

        let mut publish = None;

        let service = client::Service::new_with_config(config, |sender| {
            publish = Some(sender);
            Inner {
                receive_callback,
                error_callback,
            }
        });

        let service = rt.spawn(async move {
            match service.serve(app_name, endpoint, subscriptions).await {
                Ok(_) => {
                    // Nothing.
                }
                Err(error) => {
                    let code = match &error {
                        client::Error::Transport(_) => ClientError::Transport,
                        client::Error::ProtocolError(e) => e.into(),
                    };
                    let context = safe_string(&error.to_string());
                    error_callback(code, context.as_ptr());
                }
            }
        });

        Some(Box::new(Self {
            rt,
            _service: service,
            outbox: publish,
        }))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_client_free(self: Box<Self>) {}

    /// Publish an event on a given topic.
    ///
    /// This operation blocks if more than `outbox_size` already wait to be send.
    ///
    /// The function takes ownership of `event`.
    ///
    /// Either returns `true` on success, or `false` if the client is not connected.
    ///
    /// # Safety
    ///
    /// - event must not be NULL
    /// - `topic` must point to NULL-terminated UTF-8 string.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_client_publish(
        &mut self,
        topic: *const libc::c_char,
        event: Box<Event>,
    ) -> bool {
        let Ok(topic) = unsafe { CStr::from_ptr(topic) }.to_str() else {
            // We land here if `topic` was not valid UTF-8 which is explicitly diallowed, so no
            // need to set the global error.
            return false;
        };

        let publish = match &self.outbox {
            Some(publish) => publish,
            None => return false,
        };
        match publish.blocking_send((topic.to_owned(), event.0)) {
            Ok(()) => true,
            Err(SendError(_)) => {
                // No need to invoke the error handler as the receiving side would only be closed
                // in case of error which would already invoke it.
                false
            }
        }
    }

    /// Shut down the client.
    ///
    /// The second parameter is the number of seconds to wait for outstanding tasks to finish.
    ///
    /// This function takes ownership of the passed client pointer which must not be NULL or used
    /// by the caller after invocation.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_client_shutdown(self: Box<Self>, timeout_secs: u64) {
        self.rt.shutdown_timeout(Duration::from_secs(timeout_secs));
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct ClientConfig {
    /// Numbers of entries which can be enqueued before publishing events blocks.
    /// This value *must not* be zero.
    outbox_size: usize,
}

impl ClientConfig {
    #[unsafe(no_mangle)]
    /// Create a new client config with sensible defaults.
    extern "C" fn zws_clientconfig_new() -> Self {
        ClientConfig::default()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            outbox_size: ServiceConfig::default().outbox_size.into(),
        }
    }
}

impl From<ClientConfig> for ServiceConfig {
    /// # Safety
    ///
    /// - `ClientConfig::outbox_size` is documented to be non-zero.
    fn from(value: ClientConfig) -> Self {
        Self {
            outbox_size: unsafe { NonZeroUsize::new_unchecked(value.outbox_size) },
        }
    }
}

/// Callback invoked when a new event is received.
///
/// The first parameter is a pointer to a NULL-terminated UTF-8 string holding the topic, the
/// second parameter a non-NULL pointer to the received event.
pub type ClientReceiveCallback = extern "C" fn(*const libc::c_char, &Event);

/// Callback invoked when a new error is encountered.
///
/// The first parameter is an error code, and the second a pointer to a NULL-terminated UTF-8
/// string holding additional context. See the definition of the different error codes on how they
/// need to be handled.
pub type ClientErrorCallback = extern "C" fn(ClientError, *const libc::c_char);

/// Error conditions encountered during client processing.
#[derive(Debug)]
#[repr(C)]
pub enum ClientError {
    /// Error starting the client runtime.
    Runtime,
    /// Invalid URI.
    InvalidUri,
    /// Invalid topic.
    InvalidTopic,
    /// Unexpected message received.
    UnexpectedMessage,
    /// Transport-related error. When encountered the client needs to be recreated.
    Transport,
    /// Error received from Zeek, e.g., due to type or signature mismatches or other Zeek
    /// conditions.
    Zeek,
}

impl From<&ProtocolError> for ClientError {
    fn from(value: &ProtocolError) -> Self {
        match value {
            ProtocolError::ZeekError { .. } => ClientError::Zeek,
            ProtocolError::AckExpected
            | ProtocolError::DeserializationError(..)
            | ProtocolError::UnexpectedEventPayload(..) => ClientError::UnexpectedMessage,
            ProtocolError::AlreadySubscribed => ClientError::Transport,
        }
    }
}

pub struct Event(zeek_websocket::Event);

impl Event {
    /// Create a new event.
    ///
    /// The returned event must be freed by caller with `zws_event_free`.
    ///
    /// @param name name of the event to publish
    /// @param args arguments to the event invocation, must not be NULL
    /// @param metadata any metadata to attach to the event, can be NULL
    ///
    /// `args` and `metadata` ownership is passed to function.
    ///
    /// # Safety
    ///
    /// * `name` must point to a valid, NULL-terminated UTF-8 string.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_event_new(
        name: *const libc::c_char,
        args: Box<List>,
        metadata: Option<Box<List>>,
    ) -> Option<Box<Self>> {
        let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
            return None;
        };

        let args = args.0.into_iter().map(|x| x.0);
        let mut event = zeek_websocket::Event::new(name, args);

        if let Some(metadata) = metadata {
            event = event.with_metadata(metadata.0.iter().map(|x| x.0.clone()));
        }

        Some(Box::new(Self(event)))
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_event_free(self: Box<Self>) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_event_name(&self) -> *const u8 {
        self.0.name.as_ptr()
    }

    /// Returned value must be freed by caller with `zws_list_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_event_args(&self) -> Box<List> {
        let xs = self.0.args.iter().cloned().map(Value);
        Box::new(List(xs.collect()))
    }

    /// Returned value must be freed by caller with `zws_list_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_event_metadata(&self) -> Box<List> {
        let xs = self.0.metadata.iter().cloned().map(Value);
        Box::new(List(xs.collect()))
    }
}

#[derive(Clone, PartialEq)]
pub struct Value(pub(crate) zeek_websocket::Value);

macro_rules! getter {
    ($id:ident, $t:ty, $v:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $id(&self) -> Option<&$t> {
            if let $v(x) = &self.0 { Some(x) } else { None }
        }
    };
}

impl Value {
    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_none() -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::None))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_boolean(data: bool) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Boolean(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_count(data: u64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Count(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_integer(data: i64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Integer(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_real(data: f64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Real(data)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_timespan(nanos: i64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Timespan(
            zeek_websocket::TimeDelta::nanoseconds(nanos),
        )))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_timestamp(nanos_utc: i64) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Timestamp(
            chrono::DateTime::from_timestamp_nanos(nanos_utc).naive_utc(),
        )))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `data` must point to a valid, NULL-terminated UTF-8 string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_string(data: *const libc::c_char) -> Option<Box<Self>> {
        let data = unsafe { CStr::from_ptr(data) }.to_str().ok()?;

        Some(Box::new(Self(zeek_websocket::Value::String(
            data.to_string(),
        ))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `data` must point to a valid, NULL-terminated UTF-8 string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_enum(data: *const libc::c_char) -> Option<Box<Self>> {
        let data = unsafe { CStr::from_ptr(data) }.to_str().ok()?;
        Some(Box::new(Self(zeek_websocket::Value::EnumValue(
            data.to_string(),
        ))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// `data` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_address(data: Box<Address>) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Address(data.0)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// `addr` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_subnet(addr: Box<Address>, prefix: u8) -> Option<Box<Self>> {
        Some(Box::new(Self(zeek_websocket::Value::Subnet(
            IpNetwork::new(addr.0, prefix).ok()?,
        ))))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_new_port(port: Port) -> Box<Self> {
        Box::new(Self(zeek_websocket::Value::Port(port.into())))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_values` `Value` objects.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_vector(
        values: *const Box<Self>,
        num_values: usize,
    ) -> Box<Self> {
        let values = unsafe { slice::from_raw_parts(values, num_values) };
        let xs: Vec<_> = values.iter().map(|x| x.0.clone()).collect();
        Box::new(Self(zeek_websocket::Value::Vector(xs)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_values` `Value` objects.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_set(
        values: *const Box<Self>,
        num_values: usize,
    ) -> Box<Self> {
        let values = unsafe { slice::from_raw_parts(values, num_values) };
        let xs: Vec<_> = values.iter().map(|x| x.0.clone()).collect();
        Box::new(Self(zeek_websocket::Value::Set(xs)))
    }

    /// Returned value must be freed by caller with `zws_value_free`.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_values` `Value` objects.
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn zws_value_new_table(
        values: *const Box<TableEntry>,
        num_values: usize,
    ) -> Box<Self> {
        let values = unsafe { slice::from_raw_parts(values, num_values) };
        let xs: Vec<_> = values
            .iter()
            .map(|x| {
                TableEntry {
                    key: x.key.clone(),
                    value: x.value.clone(),
                }
                .into()
            })
            .collect();
        Box::new(Self(zeek_websocket::Value::Table(xs)))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_free(self: Box<Self>) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_type(&self) -> ValueType {
        match self.0 {
            zeek_websocket::Value::None => ValueType::None,
            zeek_websocket::Value::Boolean(_) => ValueType::Boolean,
            zeek_websocket::Value::Count(_) => ValueType::Count,
            zeek_websocket::Value::Integer(_) => ValueType::Integer,
            zeek_websocket::Value::Real(_) => ValueType::Real,
            zeek_websocket::Value::Timespan(_) => ValueType::Timespan,
            zeek_websocket::Value::Timestamp(_) => ValueType::Timestamp,
            zeek_websocket::Value::String(_) => ValueType::String,
            zeek_websocket::Value::EnumValue(_) => ValueType::EnumValue,
            zeek_websocket::Value::Address(_) => ValueType::Address,
            zeek_websocket::Value::Subnet(_) => ValueType::Subnet,
            zeek_websocket::Value::Port(_) => ValueType::Port,
            zeek_websocket::Value::Vector(_) => ValueType::Vector,
            zeek_websocket::Value::Set(_) => ValueType::Set,
            zeek_websocket::Value::Table(_) => ValueType::Table,
        }
    }

    getter!(zws_value_as_bool, bool, zeek_websocket::Value::Boolean);

    getter!(zws_value_as_count, u64, zeek_websocket::Value::Count);

    getter!(zws_value_as_integer, i64, zeek_websocket::Value::Integer);

    getter!(zws_value_as_real, f64, zeek_websocket::Value::Real);

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_timespan(&self) -> i64 {
        if let zeek_websocket::Value::Timespan(x) = &self.0 {
            return x.num_nanoseconds().unwrap_or_default();
        };
        Default::default()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_timestamp(&self) -> i64 {
        if let zeek_websocket::Value::Timestamp(x) = &self.0 {
            x.and_utc().timestamp_nanos_opt().unwrap_or_default()
        } else {
            Default::default()
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_string(&self) -> *const u8 {
        if let zeek_websocket::Value::String(x) = &self.0 {
            x.as_ptr()
        } else {
            ptr::null()
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_enumvalue(&self) -> *const u8 {
        if let zeek_websocket::Value::EnumValue(x) = &self.0 {
            x.as_ptr()
        } else {
            ptr::null()
        }
    }

    /// Returned value must be freed by caller with `zws_address_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_address(&self) -> Option<Box<Address>> {
        if let zeek_websocket::Value::Address(addr) = &self.0 {
            Some(Box::new(Address(*addr)))
        } else {
            None
        }
    }

    /// Returned value must be freed by caller with `zws_subnet_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_subnet(&self) -> Option<Box<Subnet>> {
        if let zeek_websocket::Value::Subnet(subnet) = &self.0 {
            Some(Box::new(Subnet {
                addr: Box::new(Address(subnet.ip())),
                prefix: subnet.prefix(),
            }))
        } else {
            None
        }
    }

    /// Returned value must be freed by caller.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_port(&self) -> Option<Box<Port>> {
        if let zeek_websocket::Value::Port(port) = self.0 {
            Some(Box::new(port.into()))
        } else {
            None
        }
    }

    /// Returned value must be freed by caller with `zws_list_free`.
    ///
    /// `data` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_vector(self: Box<Self>) -> Option<Box<List>> {
        if let zeek_websocket::Value::Vector(xs) = self.0 {
            let xs: Vec<_> = xs.into_iter().map(Value).collect();
            Some(Box::new(List(xs)))
        } else {
            None
        }
    }

    /// Returned value must be freed by caller with `zws_list_free`.
    ///
    /// `data` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_set(self: Box<Self>) -> Option<Box<List>> {
        if let zeek_websocket::Value::Set(xs) = self.0 {
            let xs: Vec<_> = xs.into_iter().map(Value).collect();
            Some(Box::new(List(xs)))
        } else {
            None
        }
    }

    /// Returned value must be freed by caller with `zws_table_free`.
    ///
    /// `data` ownership is passed to function.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_value_as_table(self: Box<Self>) -> Option<Box<Table>> {
        if let zeek_websocket::Value::Table(xs) = self.0 {
            let xs: Vec<_> = xs
                .into_iter()
                .map(|zeek_websocket::TableEntry { key, value }| (Value(key), Value(value)))
                .collect();
            Some(Box::new(Table(xs)))
        } else {
            None
        }
    }
}

#[repr(C)]
pub struct TableEntry {
    key: Box<Value>,
    value: Box<Value>,
}

impl From<TableEntry> for zeek_websocket::TableEntry {
    fn from(TableEntry { key, value }: TableEntry) -> Self {
        Self::new(key.0, value.0)
    }
}

#[repr(C)]
pub enum ValueType {
    None,
    Boolean,
    Count,
    Integer,
    Real,
    Timespan,
    Timestamp,
    String,
    EnumValue,
    Address,
    Subnet,
    Port,
    Vector,
    Set,
    Table,
}

pub struct List(pub(crate) Vec<Value>);

impl List {
    /// `values` ownership is passed to function.
    ///
    /// # Safety
    ///
    /// * `values` must point to an array of `num_value` `Value` objects
    ///
    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub unsafe extern "C" fn zws_list_new(values: *mut *mut Value, num_values: usize) -> Box<Self> {
        let values = if !values.is_null() && num_values != 0 {
            let values = unsafe { slice::from_raw_parts_mut(values, num_values) };
            values
                .iter_mut()
                .map(|x| *unsafe { Box::from_raw(*x) })
                .collect()
        } else {
            Vec::new()
        };

        Box::new(Self(values))
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_list_size(&self) -> usize {
        self.0.len()
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_list_entry(&self, n: usize) -> Option<&Value> {
        self.0.get(n)
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_list_free(self: Box<Self>) {}
}

pub struct Table(pub(crate) Vec<(Value, Value)>);

impl Table {
    /// Returned value must be freed by caller with `zws_list_free`.
    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_table_keys(&self) -> Box<List> {
        Box::new(List(self.0.iter().map(|(k, _)| k.clone()).collect()))
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_table_get<'a>(&'a self, key: &Value) -> Option<&'a Value> {
        self.0.iter().find(|(k, v)| k == key).map(|(k, v)| v)
    }

    #[unsafe(no_mangle)]
    #[allow(unused_variables)]
    pub extern "C" fn zws_table_free(data: Box<Self>) {}
}

#[repr(C)]
pub struct U128 {
    low: u64,
    high: u64,
}

impl From<&U128> for u128 {
    fn from(value: &U128) -> Self {
        let high = (value.high as u128) << 64;
        let low = value.low as u128;
        high | low
    }
}

impl From<u128> for U128 {
    fn from(value: u128) -> Self {
        let low = value as u64;
        let high = (value >> 64) as u64;
        U128 { low, high }
    }
}

pub struct Address(pub(crate) IpAddr);

impl Address {
    /// Returned value must be freed by caller with `zws_address_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_new_v4(data: u32) -> Box<Self> {
        Box::new(Self(IpAddr::V4(Ipv4Addr::from_bits(data))))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_free(self: Box<Address>) {}

    /// Returned value must be freed by caller with `zws_address_free`.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_new_v6(data: &U128) -> Box<Self> {
        Box::new(Self(IpAddr::V6(Ipv6Addr::from_bits(data.into()))))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_type(&self) -> AddressType {
        match &self.0 {
            IpAddr::V4(_) => AddressType::V4,
            IpAddr::V6(_) => AddressType::V6,
        }
    }

    /// Returned value must be freed by caller.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_as_v4(&self) -> Option<Box<u32>> {
        if let IpAddr::V4(addr) = &self.0 {
            return Some(Box::new(addr.to_bits()));
        }
        None
    }

    /// Returned value must be freed by caller.
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_address_as_v6(&self) -> Option<Box<U128>> {
        if let IpAddr::V6(addr) = &self.0 {
            return Some(Box::new(addr.to_bits().into()));
        }
        None
    }
}

#[repr(C)]
pub enum AddressType {
    V4,
    V6,
}

#[repr(C)]
pub struct Subnet {
    pub(crate) addr: Box<Address>,
    pub(crate) prefix: u8,
}

impl Subnet {
    #[unsafe(no_mangle)]
    pub extern "C" fn zws_subnet_free(self: Box<Self>) {}
}

#[repr(C)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    UNKNOWN,
}

impl From<Protocol> for zeek_websocket::Protocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::TCP => Self::TCP,
            Protocol::UDP => Self::UDP,
            Protocol::ICMP => Self::ICMP,
            Protocol::UNKNOWN => Self::UNKNOWN,
        }
    }
}

impl From<zeek_websocket::Protocol> for Protocol {
    fn from(value: zeek_websocket::Protocol) -> Self {
        match value {
            zeek_websocket::Protocol::TCP => Self::TCP,
            zeek_websocket::Protocol::UDP => Self::UDP,
            zeek_websocket::Protocol::ICMP => Self::ICMP,
            zeek_websocket::Protocol::UNKNOWN => Self::UNKNOWN,
        }
    }
}

#[repr(C)]
pub struct Port {
    number: u16,
    protocol: Protocol,
}

impl From<Port> for zeek_websocket::Port {
    fn from(value: Port) -> Self {
        Self::new(value.number, value.protocol.into())
    }
}

impl From<zeek_websocket::Port> for Port {
    fn from(value: zeek_websocket::Port) -> Self {
        Self {
            number: value.number(),
            protocol: value.protocol().into(),
        }
    }
}

/// Creates a CString from the give &str. If the input contains any literal `\0` the NULL and
/// any data after it is dropped from the output.
fn safe_string(s: &str) -> CString {
    let s = s.split('\0').next().unwrap_or(s);

    // Safe since we only work on characters up to any possible NULL byte.
    unsafe { CString::from_vec_unchecked(s.into()) }
}

#[cfg(test)]
mod test {
    use std::{
        ffi::{CStr, CString},
        sync::{Arc, Condvar, LazyLock, Mutex},
    };

    use crate::{Client, ClientError, Event};

    #[test]
    fn simple_client() {
        static EVENTS: LazyLock<Arc<(Mutex<Vec<Event>>, Condvar)>> =
            LazyLock::new(|| Default::default());

        extern "C" fn receive_event_callback(topic: *const libc::c_char, event: &Event) {
            let topic = unsafe { CStr::from_ptr(topic) };
            eprintln!("Event {topic:?}: {:?}", &event.0);

            EVENTS.0.lock().unwrap().push(Event(event.0.clone()));
            EVENTS.1.notify_one();
        }

        extern "C" fn receive_error_callback(code: ClientError, context: *const libc::c_char) {
            let context = unsafe { CStr::from_ptr(context) };
            eprintln!("Error {code:?}: {context:?}");
        }

        let zeek = zeek_websocket::test::MockServer::default();
        let uri = CString::new(zeek.endpoint().to_string()).unwrap();

        let app_name = c"myapp".as_ptr();

        let topics: Vec<*const libc::c_char> = vec![c"/ping".as_ptr()];

        let mut client = unsafe {
            Client::zws_client_new(
                app_name,
                uri.as_ptr(),
                topics.as_ptr(),
                topics.len(),
                receive_event_callback,
                receive_error_callback,
                None,
            )
        }
        .unwrap();

        let event = Box::new(Event(zeek_websocket::Event::new("echo", ["hi!"])));
        assert!(unsafe { client.zws_client_publish(topics[0], event) });

        let (events, cvar) = &**EVENTS;

        let mut received_events = false;
        if let Ok(events) = events.try_lock() {
            let xs = cvar.wait(events).unwrap();
            received_events |= xs.iter().any(|event| event.0.name == "echo");
        }

        assert!(received_events);
    }

    #[test]
    fn unreachable_remote() {
        let app_name = CStr::from_bytes_with_nul(b"myapp\0").unwrap().as_ptr();

        let topics: Vec<_> = vec![c"/ping".as_ptr()];

        let uri = c"ws://localhost:1".as_ptr();

        static COND: LazyLock<Arc<Condvar>> = LazyLock::new(|| Default::default());

        extern "C" fn receive_event_callback(_: *const libc::c_char, _: &Event) {}

        extern "C" fn receive_error_callback(code: ClientError, context: *const libc::c_char) {
            let context = unsafe { CStr::from_ptr(context) };
            eprintln!("Error {code:?} {context:?}");

            COND.notify_one();
        }

        let mut client = unsafe {
            Client::zws_client_new(
                app_name,
                uri,
                topics.as_ptr(),
                topics.len(),
                receive_event_callback,
                receive_error_callback,
                None,
            )
        }
        .unwrap();

        assert!(unsafe {
            client.zws_client_publish(
                topics[0],
                Box::new(Event(zeek_websocket::Event::new("echo", [1]))),
            )
        });

        let mutex = Mutex::new(());
        let _x = COND.wait(mutex.lock().unwrap()).unwrap();
    }
}
