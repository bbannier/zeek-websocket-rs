//! Client implementation
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::{
        RwLock,
        mpsc::{Receiver, Sender, channel},
    },
    task::JoinHandle,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, http::Uri},
};
use tungstenite::ClientRequestBuilder;
use typed_builder::TypedBuilder;
use zeek_websocket_types::Event;

use crate::{
    Binding,
    protocol::{self, ProtocolError},
};

/// Builder to construct a [`Client`].
#[derive(TypedBuilder)]
#[builder(
    doc,
    build_method(into = Result<Client, Error>),
    mutators(
        /// Subscribe to topic to receive events.
        pub fn subscribe<S: Into<String>>(&mut self, topic: S) {
            self.subscriptions.insert(topic.into());
        }

))]
pub struct ClientConfig {
    #[builder(via_mutators)]
    subscriptions: HashSet<String>,

    /// Zeek WebSocket endpoint to connect to.
    endpoint: Uri,

    /// String use by the client to identify itself against Zeek.
    #[builder(setter(into))]
    app_name: String,

    /// How many events to buffer before exerting backpressure.
    #[builder(default = 1024)]
    buffer_capacity: usize,
}

impl From<ClientConfig> for Result<Client, Error> {
    fn from(
        ClientConfig {
            subscriptions,
            endpoint,
            buffer_capacity,
            app_name,
        }: ClientConfig,
    ) -> Self {
        let (events_sender, events) = channel(buffer_capacity);

        let bindings: Result<_, _> = subscriptions
            .into_iter()
            .map(|topic| {
                let client = TopicHandler::new(
                    app_name.clone(),
                    Some(topic.clone()),
                    endpoint.clone(),
                    events_sender.clone(),
                );
                Ok::<(Option<String>, TopicHandler), Error>((Some(topic), client))
            })
            .collect();
        let bindings = Arc::new(RwLock::<HashMap<_, _>>::new(bindings?));

        Ok(Client {
            app_name,
            endpoint,
            bindings,
            events,
            events_sender,
        })
    }
}

/// # Tokio-based for the Zeek WebSocket API
///
/// [`Client`] implements an async client for the Zeek WebSocket API. It is intended to be run
/// inside a `tokio` runtime. The general workflow is to build a client with the [`ClientConfig`]
/// builder interface, and then either publish or receive events.
///
/// ## Example
///
/// ```no_run
/// use anyhow::Result;
/// use zeek_websocket::client::ClientConfig;
/// use zeek_websocket::Event;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let mut client = ClientConfig::builder()
///         .app_name("my_client_application")
///         .subscribe("/info")
///         .endpoint("ws://127.0.0.1:8080/v1/messages/json".try_into()?)
///         .build()?;
///
///     client
///         .publish_event("/ping", Event::new("ping", vec!["abc"]))
///         .await;
///
///     loop {
///         // Client automatically receives events on topics it sent to.
///         if let Some((_topic, event)) = client.receive_event().await? {
///             eprintln!("{event:?}");
///             break;
///         }
///     }
///
///     Ok(())
/// }
/// ```
pub struct Client {
    app_name: String,

    endpoint: Uri,
    bindings: Arc<RwLock<HashMap<Option<String>, TopicHandler>>>,

    events: Receiver<Result<(String, Event), ProtocolError>>,
    events_sender: Sender<Result<(String, Event), ProtocolError>>,
}

impl Client {
    /// Publish an [`Event`] to `topic`.
    pub async fn publish_event<S: Into<String>>(&mut self, topic: S, event: Event) {
        let topic = topic.into();

        let mut bindings = self.bindings.write().await;

        let client = if let Some(client) = bindings.get(&Some(topic.clone())) {
            // If we are subscribed to a topic use its handler for publishing the event.
            client
        } else {
            // Else use a null handler which does not receive events, but can still publish.
            bindings.entry(None).or_insert_with(|| {
                TopicHandler::new(
                    self.app_name.clone(),
                    None,
                    self.endpoint.clone(),
                    self.events_sender.clone(),
                )
            })
        };

        let _ = client.publish_sink.send((topic.clone(), event)).await;
    }

    /// Receive the next [`Event`] or [`Error`].
    ///
    /// If an event was received it will be returned as `Ok(Some((topic, event)))`.
    ///
    /// # Errors
    ///
    /// Might return a [`ProtocolError`] from the underlying binding, e.g., Zeek, or an
    /// transport-related error.
    pub async fn receive_event(&mut self) -> Result<Option<(String, Event)>, Error> {
        Ok(self.events.recv().await.transpose()?)
    }

    /// Subscribe to a topic.
    ///
    /// This is a noop if the client is already subscribed.
    pub async fn subscribe<S: Into<String>>(&mut self, topic: S) {
        let topic = topic.into();

        let mut bindings = self.bindings.write().await;
        bindings.entry(Some(topic.clone())).or_insert_with(|| {
            TopicHandler::new(
                self.app_name.clone(),
                Some(topic),
                self.endpoint.clone(),
                self.events_sender.clone(),
            )
        });
    }

    /// Unsubscribe from a topic.
    ///
    /// This is a noop if the client was not subscribed.
    pub async fn unsubscribe(&mut self, topic: &str) -> bool {
        let mut bindings = self.bindings.write().await;
        bindings.remove(&Some(topic.to_string())).is_some()
    }
}

struct TopicHandler {
    _loop: JoinHandle<Result<(), Error>>,
    publish_sink: Sender<(String, Event)>,
}

impl TopicHandler {
    fn new(
        app_name: String,
        topic: Option<String>,
        endpoint: Uri,
        events_sender: Sender<Result<(String, Event), ProtocolError>>,
    ) -> Self {
        let (publish_sink, mut publish) = channel(1);

        let loop_ = tokio::spawn(async move {
            let topics = if let Some(topic) = &topic {
                vec![topic.clone()]
            } else {
                vec![]
            };
            let mut binding = Binding::new(topics);

            let endpoint =
                ClientRequestBuilder::new(endpoint).with_header("X-Application-Name", app_name);

            let (mut stream, ..) = connect_async(endpoint).await?;

            loop {
                tokio::select! {
                    r = publish.recv() => {
                        let Some((topic, event)) = r else { return Ok(()); };
                        binding.publish_event::<String>(topic, event);
                    }
                    s = stream.next() => {
                        if let Ok(message) = match s {
                            Some(payload) => match payload {
                                Ok(p) => p.try_into(),
                                Err(e) => {
                                    if let Some(topic) = &topic {
                                        handle_transport_error(e, &mut binding, topic)?;
                                    }
                                    continue;
                                },
                            },

                            None => continue,
                        } {
                            binding.handle_incoming(message)?;
                        }
                    }
                };

                while let Some(bin) = binding.outgoing() {
                    if let Err(e) = stream.send(tungstenite::Message::binary(bin)).await
                        && let Some(topic) = &topic
                    {
                        handle_transport_error(e, &mut binding, topic)?;
                    }
                }

                while let Some(payload) = binding.receive_event().transpose() {
                    let _ = events_sender.send(payload).await;
                }
            }
        });

        TopicHandler {
            _loop: loop_,
            publish_sink,
        }
    }
}

/// Error enum for client-related errors.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failure in websocket transport: {0}")]
    Transport(String),
    #[error("protocol-related error: {0}")]
    ProtocolError(#[from] protocol::ProtocolError),
}

impl From<tungstenite::Error> for Error {
    fn from(value: tungstenite::Error) -> Self {
        Self::Transport(value.to_string())
    }
}

/// Error handling for transport errors.
///
/// Returns a `Ok(())` if the incoming could be handled, or an `Err` if it should be propagated up.
fn handle_transport_error(
    e: tungstenite::Error,
    binding: &mut Binding,
    topic: &str,
) -> Result<(), Error> {
    match e {
        // Errors we can handle by gracefully resubscribing.
        tungstenite::Error::AttackAttempt
        | tungstenite::Error::AlreadyClosed
        | tungstenite::Error::ConnectionClosed
        | tungstenite::Error::Io(_) => {
            *binding = Binding::new(vec![topic]);
            Ok(())
        }

        // Errors we bail on and bubble up to the user.
        tungstenite::Error::Protocol(_)
        | tungstenite::Error::WriteBufferFull(_)
        | tungstenite::Error::Capacity(_)
        | tungstenite::Error::Tls(_)
        | tungstenite::Error::Url(_)
        | tungstenite::Error::Http(_)
        | tungstenite::Error::HttpFormat(_)
        | tungstenite::Error::Utf8(_) => Err(Error::from(e)),
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use zeek_websocket_types::Event;

    use crate::{client::ClientConfig, test::MockServer};

    #[tokio::test]
    async fn basic() {
        let endpoint = "ws://127.0.0.1";
        let mut client = ClientConfig::builder()
            .endpoint(endpoint.try_into().unwrap())
            .app_name("foo")
            .subscribe("/info")
            .build()
            .unwrap();

        client
            .publish_event("/info", Event::new("info", ["hi!"]))
            .await;

        client
            .publish_event("/not-yet-subscribed", Event::new("info", ["hi!"]))
            .await;

        tokio::select! {
            _e = client.receive_event() => {}
            _timeout = tokio::time::sleep(Duration::from_millis(10)) => {}
        };

        client.subscribe("/info").await;
        client.subscribe("/foo").await;

        client.unsubscribe("/info").await;
        client.unsubscribe("/foo").await;
    }

    #[tokio::test]
    async fn publish_receive() {
        let mock = MockServer::default();

        let topic = "/foo".to_owned();
        let mut client = ClientConfig::builder()
            .endpoint(mock.endpoint().try_into().unwrap())
            .app_name(&topic)
            .subscribe("/foo")
            .build()
            .unwrap();

        let echo = Event::new("echo", ["hi"]);
        client.publish_event(&topic, echo.clone()).await;
        assert_eq!(client.receive_event().await, Ok(Some((topic, echo))));
    }
}
