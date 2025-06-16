//! # Sans I/O-style protocol wrapper for the Zeek API
//!
//! Instead of providing a full-fledged client [`Binding`] encapsulates the Zeek WebSocket
//! protocol [sans I/O style](https://sans-io.readthedocs.io/). It provides the following methods:
//!
//! - [`Binding::handle_input`] injects data received over a network connection into the
//!   `Binding` object
//! - [`Binding::enqueue`] to enqueue a message for Zeek
//! - [`Binding::incoming`] gets the next message received from Zeek
//! - [`Binding::outgoing`] gets the next data payload for sending to Zeek
//!
//! A full client implementation will typically implement some form of event loop.
//!
//! ## Example
//!
//! ```no_run
//! use zeek_websocket::*;
//!
//! // Open an underlying WebSocket connection to a Zeek endpoint.
//! let (mut socket, _) = tungstenite::connect("ws://127.0.0.1:8080/v1/messages/json").unwrap();
//!
//! // Create a connection.
//! let mut conn = Binding::new(&["/ping"]);
//!
//! // The event loop.
//! loop {
//!     // If we have any outgoing messages send at least one.
//!     if let Some(data) = conn.outgoing() {
//!         socket.send(tungstenite::Message::binary(data)).unwrap();
//!     }
//!
//!     // Receive the next message and handle it.
//!     if let Ok(msg) = socket.read().unwrap().try_into() {
//!         conn.handle_input(msg);
//!     }
//!
//!     // If we received a `ping` event, respond with a `pong`.
//!     if let Some((topic, event)) = conn.next_event() {
//!         if event.name == "ping" {
//!             conn.enqueue_event(topic, Event::new("pong", event.args.clone()));
//!         }
//!     }
//! }
//! ```

use std::collections::VecDeque;

use thiserror::Error;
use tungstenite::Bytes;
use zeek_websocket_types::{Data, Event, Message};

use crate::types::Subscriptions;

/// Protocol wrapper for a Zeek WebSocket connection.
///
/// See the [module documentation](crate::protocol) for an introduction
pub struct Binding {
    state: State,
    subscriptions: Subscriptions,

    inbox: Inbox,
    outbox: Outbox,
}

enum State {
    Subscribing,
    Subscribed,
}

impl Binding {
    /// Create a new `Binding` with the given [`Subscriptions`].
    ///
    /// ```
    /// # use zeek_websocket::Binding;
    /// let conn = Binding::new(&["topic"]);
    /// ```
    #[must_use]
    pub fn new<S>(subscriptions: S) -> Self
    where
        S: Into<Subscriptions>,
    {
        let subscriptions = subscriptions.into();
        Self {
            state: State::Subscribing,
            inbox: Inbox(VecDeque::new()),
            outbox: Outbox(VecDeque::from([subscriptions.clone().into()])),
            subscriptions,
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

    /// Get the next incoming event.
    ///
    /// In contrast to [`Binding::incoming`] this discards any non-`Event` messages which were received.
    pub fn next_event(&mut self) -> Option<(String, Event)> {
        self.inbox.next_event()
    }

    /// Enqueue a message for sending.
    ///
    /// # Errors
    ///
    /// Will return [`ProtocolError::SendOnNonSubscribed`] if the binding is not subscribed to the
    /// topic of the message.
    pub fn enqueue(&mut self, message: Message) -> Result<(), ProtocolError> {
        match message {
            Message::DataMessage { topic, data } => {
                let is_subscribed = self
                    .subscriptions
                    .0
                    .iter()
                    .any(|s| s.as_str() == topic.as_str());

                if is_subscribed {
                    self.outbox.enqueue(Message::DataMessage { topic, data });
                } else {
                    return Err(ProtocolError::SendOnNonSubscribed(
                        topic,
                        self.subscriptions.clone(),
                        data,
                    ))?;
                }
            }
            _ => self.outbox.enqueue(message),
        }

        Ok(())
    }

    /// Enqueue an event for sending.
    ///
    /// # Errors
    ///
    /// See [`Binding::enqueue`] for possible errors.
    pub fn enqueue_event<S>(&mut self, topic: S, event: Event) -> Result<(), ProtocolError>
    where
        S: Into<String>,
    {
        self.enqueue(Message::new_data(topic.into(), event))
    }

    /// Split the `Binding` into an [`Inbox`] and [`Outbox`].
    ///
    /// <div class="warning">
    /// Clients can only publish to topics they are subscribed to. While <code>Binding</code>
    /// detects if it sees a publish on topic it is not subscribed to, this
    /// is not provided by <code>Outbox</code>, so it is suggested to first subscribe to all topics
    /// we want to publish on before splitting the <code>Binding</code>.
    /// </div>
    #[must_use]
    pub fn split(self) -> (Inbox, Outbox) {
        (self.inbox, self.outbox)
    }
}

/// Receiving side of a [`Binding`].
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

    /// Get the next event.
    ///
    /// In contrast to [`Inbox::next_message`] this discards any non-`Event` messages which were received.
    pub fn next_event(&mut self) -> Option<(String, Event)> {
        while let Some(message) = self.next_message() {
            if let Message::DataMessage {
                topic,
                data: Data::Event(event),
            } = message
            {
                return Some((topic, event));
            }
        }

        None
    }
}

/// Sending side of [`Binding`].
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

    /// Enqueue an event for sending.
    pub fn enqueue_event<S>(&mut self, topic: S, event: Event)
    where
        S: Into<String>,
    {
        self.enqueue(Message::new_data(topic.into(), event));
    }
}

/// Error enum for protocol-related errors.
#[derive(Error, Debug, PartialEq)]
pub enum ProtocolError {
    /// received an ACK while already subscribed
    #[error("received an ACK while already subscribed")]
    AlreadySubscribed,

    #[error("attempted to send on topic '{0}' but only subscribed to '{1}'")]
    SendOnNonSubscribed(String, Subscriptions, Data),
}

#[cfg(test)]
mod test {
    use crate::{
        protocol::{Binding, ProtocolError},
        types::{Data, Event, Message, Subscriptions, Value},
    };

    fn ack() -> Message {
        Message::Ack {
            endpoint: "mock".into(),
            version: "0.1".into(),
        }
    }

    #[test]
    fn recv() {
        let topic = "foo";

        let mut conn = Binding::new(&[topic]);

        // Nothing received yet,
        assert_eq!(conn.incoming(), None);

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        conn.handle_input(ack().into()).unwrap();

        assert!(matches!(conn.incoming(), Some(Message::Ack { .. })));

        // No new input received.
        assert_eq!(conn.incoming(), None);
        assert_eq!(conn.next_event(), None);

        // Receive a single event.
        conn.handle_input(Message::new_data(topic, Event::new("ping", Vec::<Value>::new())).into())
            .unwrap();

        assert!(matches!(
            conn.incoming(),
            Some(Message::DataMessage {
                data: Data::Event(..),
                ..
            })
        ));
    }

    #[test]
    fn send() {
        let mut conn = Binding::new(&["foo"]);

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        conn.handle_input(ack().into()).unwrap();

        // Send an event.
        conn.enqueue_event("foo", Event::new("ping", Vec::<Value>::new()))
            .unwrap();

        // Event payload should be in outbox.
        let msg =
            Message::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        dbg!(&msg);
        assert!(matches!(
            msg,
            Message::DataMessage {
                data: Data::Event(..),
                ..
            }
        ));
    }

    #[test]
    fn split() {
        let (mut inbox, mut outbox) = Binding::new(&["foo"]).split();

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(outbox.next_data().unwrap())).unwrap();
        inbox.handle(ack().into());

        assert!(matches!(inbox.next_message(), Some(Message::Ack { .. })));
    }

    #[test]
    fn send_on_non_subscribed() {
        let mut conn = Binding::new(&["foo"]);

        // The initial message is the subscription to `["foo"]`.
        let message = tungstenite::Message::binary(conn.outgoing().unwrap());
        let subscription = Subscriptions::try_from(message).unwrap();
        assert_eq!(subscription, Subscriptions::from(&["foo"]));

        // Sent a message on `"bar"` to which we are not subscribed.
        let event = Event::new("ping", vec!["ping on 'bar'"]);
        assert_eq!(
            conn.enqueue_event("bar", event.clone()),
            Err(ProtocolError::SendOnNonSubscribed(
                "bar".to_string(),
                Subscriptions::from(&["foo"]),
                Data::Event(event),
            ))
        );
    }

    #[test]
    fn duplicate_ack() {
        let mut conn = Binding::new(&["foo"]);

        // Handle subscription.
        Subscriptions::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        conn.handle_input(ack().into()).unwrap();

        // The initial message we received is the ACK for subscription.
        assert!(matches!(conn.incoming(), Some(Message::Ack { .. })));

        // Detect if we see another, unexpected ACK.
        assert_eq!(
            conn.handle_input(ack().into()),
            Err(ProtocolError::AlreadySubscribed)
        );
    }

    #[test]
    fn next_incoming() {
        let mut conn = Binding::new(Subscriptions(Vec::new()));

        // Put an ACK and an event into the inbox.
        let _ = conn.handle_input(ack());
        let _ = conn.handle_input(Message::new_data(
            "topic",
            Event::new("ping", Vec::<Value>::new()),
        ));

        // Event though we have an ACK in the inbox `next_event`
        // discards it and returns the event.
        let (topic, event) = conn.next_event().unwrap();
        assert_eq!(topic, "topic");
        assert_eq!(event.name, "ping");

        assert_eq!(conn.incoming(), None);
    }

    #[test]
    fn enqueue_event() {
        let mut conn = Binding::new(&["foo"]);
        // Consume the subscription.
        conn.outgoing().unwrap();

        conn.enqueue_event("foo", Event::new("ping", Vec::<Value>::new()))
            .unwrap();
        let message =
            Message::try_from(tungstenite::Message::binary(conn.outgoing().unwrap())).unwrap();
        let Message::DataMessage {
            topic,
            data: Data::Event(event),
        } = message
        else {
            panic!()
        };
        assert_eq!(topic, "foo");
        assert_eq!(event.name, "ping");
    }
}
