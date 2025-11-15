use zeek_websocket::{
    Event, Subscriptions,
    client::Outbox,
    client::{Service, ZeekClient},
};

struct Client {
    sender: Option<Outbox>,
}

impl ZeekClient for Client {
    async fn connected(&mut self, _ack: zeek_websocket::Message) {
        // Once connected send a single echo event. The server will send the
        // event back to use.
        if let Some(sender) = &self.sender {
            sender
                .send(("/ping".to_owned(), Event::new("ping", ["hi!"])))
                .await
                .unwrap();
        }
    }

    async fn event(&mut self, _topic: String, _event: zeek_websocket::Event) {
        // If we see the `pong` from the `ping` we sent when we connected, drop the sender to
        // indicate we are done.
        if &_event.name == "pong" {
            self.sender.take();
        }
    }

    async fn error(&mut self, _error: zeek_websocket::protocol::ProtocolError) {
        unimplemented!()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Service::new(|sender| Client {
        sender: Some(sender),
    });

    service
        .serve(
            "example-client",
            "ws://localhost:8080/v1/messages/json".try_into()?,
            Subscriptions::from(&["/ping"]),
        )
        .await?;

    Ok(())
}
