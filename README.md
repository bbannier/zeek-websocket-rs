# Rust types for working with Zeek over WebSocket

This library provides types for interacting with [Zeek](https://zeek.org)'s
WebSocket API.

The Zeek API uses JSON for data transport, so most likely one will need a crate
like [`serde_json`](https://docs.rs/serde_json/) to serialize the data for
transport. For convenience we provide automatic conversion from a to
[`tungstenite`](https://docs.rs/tungstenite/) messages.

While Zeek supports arbitrary backends for cluster communication, currently all
backends still follow [Broker's data model and WebSocket
API](https://docs.zeek.org/projects/broker/en/current/web-socket.html), see
their documentation for details on the protocol.

Incoming and outgoing Zeek messages are modelled by [`Message`] which holds the
topic of the message, and the actual [`Data`] payload, e.g., events.

## Example

Zeek's WebSocket API operates in the following phases, here using
[`tungstenite`](https://docs.rs/tungstenite/) for simplicity.

### Connecting the client

```no_run
use tungstenite::connect;

let uri = "ws://127.0.0.1:4711/v1/messages/json";
let (mut socket, _) = connect(uri).unwrap();
```

### Subscribing the client

The clients sends a list of topics for subscription. The server responds with
an ACK message.

```no_run
# use tungstenite::connect;
# let uri = "ws://127.0.0.1:4711/v1/messages/json";
# let (mut socket, _) = connect(uri).unwrap();
use zeek_websocket::{Message, Subscriptions};

// Subscribe to zero or more topics.
let topics = Subscriptions(vec!["/topic/1".to_string(), "/topic/2".to_string()]);
socket.send(topics.try_into().unwrap()).unwrap();

// The server responds with `Message::Ack`.
let Ok(data) = socket.read() else {
    panic!("lost connection");
};
let msg = data.try_into().unwrap();
assert!(matches!(msg, Message::Ack { .. }));
```

### Receiving events

The client now receives messages from Zeek on the topics it subscribed to.

```no_run
# use tungstenite::connect;
# let uri = "ws://127.0.0.1:4711/v1/messages/json";
# let (mut socket, _) = connect(uri).unwrap();
use zeek_websocket::{Data, Message};

while let Ok(data) = socket.read() {
    if let Ok(Message::DataMessage {
        topic,
        data: Data::Event(event),
    }) = data.try_into()
    {
        println!("Received event on '{topic}': {event:?}");
    }
}
```

### Sending events

```no_run
# use tungstenite::connect;
# let uri = "ws://127.0.0.1:4711/v1/messages/json";
# let (mut socket, _) = connect(uri).unwrap();
use zeek_websocket::types::Value;
use zeek_websocket::{Data, Event, Message};

let event = Message::DataMessage {
    topic: "/topic/1".into(),
    data: Data::Event(Event {
        name: "hello".into(),
        args: vec![Value::String("server".into())],
        metadata: vec![],
    }),
}
.try_into()
.unwrap();

socket.send(event).unwrap();
```
