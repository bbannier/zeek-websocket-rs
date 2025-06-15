use tungstenite::connect;
use zeek_websocket::{Event, Subscriptions, protocol::Binding};

fn main() -> anyhow::Result<()> {
    let uri = "ws://127.0.0.1:8080/v1/messages/json";

    let (mut socket, _) = connect(uri)?;
    let mut conn = Binding::new(Subscriptions::from(vec!["/ping"]));

    loop {
        // If we have any outgoing messages send at least one.
        if let Some(data) = conn.outgoing() {
            socket.send(tungstenite::Message::binary(data))?;
        }

        // Receive the next message and handle it.
        if let Ok(msg) = socket.read()?.try_into() {
            conn.handle_input(msg)?;
        }

        // Wait for the next event.
        if let Some((topic, Event { name, args, .. })) = conn.next_event() {
            // If we received a `ping` event, respond with a `pong`.
            if name == "ping" {
                conn.enqueue_event(topic, Event::new("pong", args));
            }
        }
    }
}
