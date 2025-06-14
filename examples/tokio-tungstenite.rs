use std::{
    sync::{
        Arc,
        atomic::{self, AtomicU64},
    },
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt, TryStreamExt};
use tokio_tungstenite::connect_async;
use tungstenite::client::IntoClientRequest;
use zeek_websocket::{Data, Event, Message, Subscriptions, protocol::Connection};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let request = "ws://127.0.0.1:8080/v1/messages/json".into_client_request()?;

    let (stream, _response) = connect_async(request).await?;
    let (mut tx, mut rx) = stream.split();

    const TOPIC: &str = "/ping";

    let (mut inbox, mut outbox) = Connection::new(Subscriptions::from(vec![TOPIC])).split();

    let num_sent = Arc::new(AtomicU64::new(0));
    let num_received = Arc::new(AtomicU64::new(0));

    let duration = Duration::from_secs(10);
    eprintln!("sending for {duration:?}");

    let count = num_sent.clone();
    let sender = tokio::spawn(async move {
        let start = Instant::now();
        let end = start + duration;

        loop {
            outbox.enqueue(Message::new_data(TOPIC, Event::new("ping", vec!["hohi"])));

            while let Some(data) = outbox.next_data() {
                tx.send(tungstenite::Message::binary(data)).await.unwrap();
            }

            count.fetch_add(1, atomic::Ordering::Relaxed);

            let now = Instant::now();
            if now > end {
                break;
            }
        }
    });

    let count = num_received.clone();
    let receiver = tokio::spawn(async move {
        loop {
            let Ok(Some(received)) = rx.try_next().await else {
                break;
            };

            if let Ok(msg) = received.try_into() {
                inbox.handle(msg);
            }

            if let Some(Message::DataMessage {
                data: Data::Event(event),
                ..
            }) = inbox.next_message()
            {
                if event.name == "pong" {
                    count.fetch_add(1, atomic::Ordering::Relaxed);
                }
            }
        }
        // in_.handle_input(received);
    });

    tokio::select! {
        _ = sender => {},
        _= receiver => {}
    };

    eprintln!("sent {num_sent:?} pings and received {num_received:?} pongs back");

    Ok(())
}
