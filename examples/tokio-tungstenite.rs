use std::{
    sync::{
        Arc,
        atomic::{self, AtomicU64},
    },
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tungstenite::client::IntoClientRequest;
use zeek_websocket::{
    types::Value,
    {Data, Event, Message, Subscriptions},
};

#[tokio::main]
async fn main() {
    let request = "ws://127.0.0.1:8080/v1/messages/json"
        .into_client_request()
        .unwrap();

    let (stream, _response) = connect_async(request).await.unwrap();
    let (mut tx, mut rx) = stream.split();

    const TOPIC: &str = "/ping";

    // Subscribe client.
    tx.send(Subscriptions(vec![TOPIC.into()]).try_into().unwrap())
        .await
        .unwrap();

    let num_sent = Arc::new(AtomicU64::new(0));
    let num_received = Arc::new(AtomicU64::new(0));

    let duration = Duration::from_secs(10);
    eprintln!("sending for {duration:?}");

    let count = num_sent.clone();
    let sender = tokio::spawn(async move {
        let start = Instant::now();
        let end = start + duration;

        loop {
            tx.send(
                Message::DataMessage {
                    topic: TOPIC.into(),
                    data: Data::Event(Event {
                        name: "ping".into(),
                        args: vec![Value::from("hohi")],
                        metadata: vec![],
                    }),
                }
                .try_into()
                .unwrap(),
            )
            .await
            .unwrap();
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
            while let Some(Ok(data)) = rx.next().await {
                let Ok(msg) = data.try_into() else {
                    continue;
                };

                if let Message::DataMessage {
                    data: Data::Event(event),
                    ..
                } = msg
                {
                    if event.name == "pong" {
                        count.fetch_add(1, atomic::Ordering::Relaxed);
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = sender => {},
        _= receiver => {}
    };

    eprintln!("sent {num_sent:?} pings and received {num_received:?} pongs back");
}
