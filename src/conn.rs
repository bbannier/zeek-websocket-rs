use std::collections::VecDeque;

use thiserror::Error;
use tungstenite::Bytes;

use crate::{Message, Subscriptions};

/// Sans I/O-style bindings for the Zeek API
///
/// Instead of providing a full-fledged client `Connection` encapsulates the Zeek WebSocket
/// protocol [sans I/O style](https://sans-io.readthedocs.io/). We provide the following methods:
///
/// - [`Connection::handle_input`] injects data received over a network connection into the
///   `Connection` object
/// - [`Connection::enqueue`] to enqueue a message for Zeek
/// - [`Connection::incoming`] gets the next message received from Zeek
/// - [`Connection::outgoing`] gets the next data payload for sending to Zeek
///
/// A full client implementation will typically implement some form of event loop.
///
/// ## Example
///
/// ```no_run
/// use zeek_websocket::*;
///
/// // Open an underlying WebSocket connection to a Zeek endpoint.
/// let (mut socket, _) = tungstenite::connect("ws://127.0.0.1:8080/v1/messages/json").unwrap();
///
/// // Create a connection.
/// let topic = "/ping";
/// let mut conn = Connection::new(Subscriptions::from(vec![topic]));
///
/// // The event loop.
/// loop {
///     // If we have any outgoing messages send at least one.
///     if let Some(data) = conn.outgoing() {
///         socket.send(tungstenite::Message::binary(data)).unwrap();
///     }
///
///     // Receive the next message and handle it.
///     let message = socket.read().unwrap();
///     if let Ok(msg) = message.try_into() {
///         conn.handle_input(msg);
///     }
///
///     // If we received a `ping` event, respond with a `pong`.
///     if let Some(Message::DataMessage {
///         data: Data::Event(event),
///         ..
///     }) = conn.incoming()
///     {
///         if event.name == "ping" {
///             conn.enqueue(Message::new_data(
///                 topic,
///                 Event::new("pong", event.args.clone()),
///             ));
///         }
///     }
/// }
/// ```
pub struct Connection {
    state: State,
    subscriptions: Subscriptions,

    inbox: Inbox,
    outbox: Outbox,
}

enum State {
    Subscribing,
    Subscribed,
}

impl Connection {
    /// Create a new `Connection` with the given [`Subscriptions`].
    #[must_use]
    pub fn new(subscriptions: Subscriptions) -> Self {
        Self {
            state: State::Subscribing,
            subscriptions: subscriptions.clone(),
            inbox: Inbox(VecDeque::new()),
            outbox: Outbox(VecDeque::from([subscriptions.into()])),
        }
    }

    /// Handle received message.
    ///
    /// Returns `true` if the data was converted to a [`Message`] and added
    /// to the inbox, or `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns a [`ProtocolError::AlreadySubscribed`] if we saw an unexpected ACK.
    pub fn handle_input(&mut self, message: Message) -> Result<(), ProtocolError> {
        if let Message::Ack { .. } = &message {
            match self.state {
                State::Subscribing => {
                    self.state = State::Subscribed;
                }
                State::Subscribed => return Err(ProtocolError::AlreadySubscribed),
            }
        }

        self.inbox.handle(message);
        Ok(())
    }

    /// Get next incoming message.
    #[must_use]
    pub fn incoming(&mut self) -> Option<Message> {
        self.inbox.next_message()
    }

    /// Get next data enqueued for sending.
    pub fn outgoing(&mut self) -> Option<Bytes> {
        self.outbox.next_data()
    }

    /// Enqueue a message for sending.
    ///
    /// If the `Connection` is not already subscribed to the topic
    /// of `message` the `Connection` will be resubscribed.
    pub fn enqueue(&mut self, message: Message) {
        if let Message::DataMessage { topic, .. } = &message {
            let is_subscribed = &self
                .subscriptions
                .0
                .iter()
                .any(|s| s.as_str() == topic.as_str());

            if !is_subscribed {
                self.subscriptions.0.push(topic.into());
                self.outbox.enqueue(self.subscriptions.clone());
            }
        }

        self.outbox.enqueue(message);
    }

    /// Split the `Connection` into an [`Inbox`] and [`Outbox`].
    ///
    /// <div class="warning">
    /// Clients can only publish to topics they are subscribed to. While <code>Connection</code>
    /// gracefully resubscribes if it sees a event publish on topic it is not subscribed to, this
    /// is not provided by <code>Outbox</code>, so it is suggested to first subscribe to all topics
    /// we want to publish on before splitting the <code>Connection</code>.
    /// </div>
    #[must_use]
    pub fn split(self) -> (Inbox, Outbox) {
        (self.inbox, self.outbox)
    }
}

/// Receiving side of a [`Connection`].
pub struct Inbox(VecDeque<Message>);

impl Inbox {
    /// Handle received message.
    pub fn handle(&mut self, message: Message) {
        self.0.push_back(message);
    }

    /// Get next incoming message.
    #[must_use]
    pub fn next_message(&mut self) -> Option<Message> {
        self.0.pop_front()
    }
}

/// Sending side of [`Connection`].
pub struct Outbox(VecDeque<tungstenite::Message>);

impl Outbox {
    /// Get next data enqueued for sending.
    pub fn next_data(&mut self) -> Option<Bytes> {
        self.0.pop_front().map(tungstenite::Message::into_data)
    }

    /// Enqueue a new message.
    pub fn enqueue<M>(&mut self, message: M)
    where
        M: Into<tungstenite::Message>,
    {
        self.0.push_back(message.into());
    }
}

/// Error enum for protocol-related errors.
#[derive(Error, Debug, PartialEq)]
pub enum ProtocolError {
    /// received an ACK while already subscribed
    #[error("received an ACK while already subscribed")]
    AlreadySubscribed,
}

#[cfg(test)]
mod test {
    use crate::{
        Data, Event, Message, Subscriptions,
        protocol::{Connection, ProtocolError},
        types::Value,
    };
    use futures_util::{SinkExt, TryStreamExt};
    use tokio::{net::TcpStream, sync::mpsc::Sender};
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
    use ws_mock::ws_mock_server::{WsMock, WsMockServer};

    type Transport = WebSocketStream<MaybeTlsStream<TcpStream>>;

    async fn mock() -> anyhow::Result<(Transport, Sender<tungstenite::Message>, WsMockServer)> {
        let server = WsMockServer::start().await;
        let (rx, tx) = tokio::sync::mpsc::channel::<tungstenite::Message>(1024);

        WsMock::new().forward_from_channel(tx).mount(&server).await;
        rx.send(
            Message::Ack {
                endpoint: "mock".into(),
                version: "0.1".into(),
            }
            .into(),
        )
        .await
        .unwrap();

        let (transport, _) = connect_async(server.uri().await).await.unwrap();

        Ok((transport, rx, server))
    }

    async fn subscribe(data: &[u8], transport: &mut Transport) {
        let message = tungstenite::Message::from(data);

        // Just validate that we indeed have a subscription.
        assert!(Subscriptions::try_from(message.clone()).is_ok());

        transport.send(message).await.unwrap()
    }

    #[tokio::test]
    async fn recv() {
        let (mut transport, rx, _) = mock().await.unwrap();

        let topic = "foo";

        // Simply respond with a single event.
        rx.send(Message::new_data(topic, Event::new("ping", Vec::<Value>::new())).into())
            .await
            .unwrap();

        let mut conn = Connection::new(Subscriptions::from(vec![topic]));

        // Send the subscription.
        subscribe(&conn.outgoing().unwrap(), &mut transport).await;

        // Nothing received yet,
        assert_eq!(conn.incoming(), None);

        conn.handle_input(
            transport
                .try_next()
                .await
                .unwrap()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(conn.incoming(), Some(Message::Ack { .. })));

        // No new input received.
        assert_eq!(conn.incoming(), None);

        // Receive more input.
        conn.handle_input(
            transport
                .try_next()
                .await
                .unwrap()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            conn.incoming(),
            Some(Message::DataMessage {
                data: Data::Event(..),
                ..
            })
        ),);
    }

    #[tokio::test]
    async fn send() {
        let (mut transport, ..) = mock().await.unwrap();
        let mut conn = Connection::new(Subscriptions::from(vec!["foo"]));

        // Send the subscription.
        subscribe(&conn.outgoing().unwrap(), &mut transport).await;

        // Send an event.
        conn.enqueue(Message::new_data(
            "foo",
            Event::new("ping", Vec::<Value>::new()),
        ));

        let msg = conn.outgoing().unwrap();
        transport
            .send(tungstenite::Message::binary(msg))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn split() {
        let (mut transport, ..) = mock().await.unwrap();
        let (mut inbox, mut outbox) = Connection::new(Subscriptions::from(vec!["foo"])).split();

        // Send the subscription.
        transport
            .send(tungstenite::Message::binary(outbox.next_data().unwrap()))
            .await
            .unwrap();

        inbox.handle(
            transport
                .try_next()
                .await
                .unwrap()
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert!(matches!(inbox.next_message(), Some(Message::Ack { .. })));
    }

    #[tokio::test]
    async fn resubscribe() {
        let mut conn = Connection::new(Subscriptions::from(vec!["foo"]));

        // The initial message is the subscription to `["foo"]`.
        let message = tungstenite::Message::binary(conn.outgoing().unwrap());
        let subscription = Subscriptions::try_from(message).unwrap();
        assert_eq!(subscription, Subscriptions::from(vec!["foo"]));

        // Sent a message on `"bar"` to which we are not subscribed.
        let event = Message::new_data("bar", Event::new("ping", vec!["ping on 'bar'"]));
        conn.enqueue(event.clone());

        // We expect to see a resubscription which adds `"bar"`.
        let message = tungstenite::Message::binary(conn.outgoing().unwrap());
        let ack = Subscriptions::try_from(message).unwrap();
        assert_eq!(ack, Subscriptions::from(vec!["foo", "bar"]));

        // The original message follows after.
        let message = tungstenite::Message::binary(conn.outgoing().unwrap());
        let message = Message::try_from(message);
        assert_eq!(message, Ok(event));
    }

    #[tokio::test]
    async fn duplicate_ack() {
        let (mut transport, rx, _) = mock().await.unwrap();

        let mut conn = Connection::new(Subscriptions::from(vec!["foo"]));

        // The initial message we received is the ACK for subscription. Reinject it so we receive
        // multiple ACKs.
        let subscription = tungstenite::Message::binary(conn.outgoing().unwrap());
        transport.send(subscription).await.unwrap();

        let ack = transport.try_next().await.unwrap().unwrap();
        assert!(matches!(ack.clone().try_into(), Ok(Message::Ack { .. })));
        conn.handle_input(ack.clone().try_into().unwrap()).unwrap();
        rx.send(ack).await.unwrap();

        let ack = transport.try_next().await.unwrap().unwrap();
        assert_eq!(
            conn.handle_input(ack.clone().try_into().unwrap()),
            Err(ProtocolError::AlreadySubscribed)
        );
    }
}
