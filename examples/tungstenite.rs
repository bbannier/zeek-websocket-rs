use tungstenite::connect;
use zeek_websocket::{Event, Message, Subscriptions, protocol::Binding};

fn main() -> anyhow::Result<()> {
    let uri = "ws://127.0.0.1:8080/v1/messages/json";

    let topic = "/ping";

    let (mut socket, _) = connect(uri)?;
    let mut conn = Binding::new(Subscriptions::from(vec![topic]));

    loop {
        // If we have any outgoing messages send at least one.
        if let Some(data) = conn.outgoing() {
            socket.send(tungstenite::Message::binary(data))?;
        }

        // Receive the next message and handle it.
        if let Ok(msg) = socket.read()?.try_into() {
            conn.handle_input(msg)?;
        }

        // If we received a `ping` event, respond with a `pong`.

        // Wait for the next event.
        if let Some((topic, Event { name, args, .. })) = conn.next_event() {
            // If we received a `ping` event, respond with a `pong`.
            if name == "ping" {
                conn.enqueue(Message::new_data(topic, Event::new("pong", args)));
            }
        }
    }
}
