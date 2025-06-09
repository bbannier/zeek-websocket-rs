use tungstenite::connect;
use zeek_websocket::{Data, Event, Message, Subscriptions};

fn main() {
    let uri = "ws://127.0.0.1:8080/v1/messages/json";

    let (mut socket, _) = connect(uri).unwrap();

    // Subscribe client.
    let subscriptions = Subscriptions::from(vec!["/ping"]);
    socket.send(subscriptions.try_into().unwrap()).unwrap();

    // Write event.
    socket
        .send(
            Message::new_data("/ping", Event::new("ping", vec!["hohi"]))
                .try_into()
                .unwrap(),
        )
        .unwrap();

    while let Ok(data) = socket.read() {
        let Ok(msg) = data.try_into() else {
            continue;
        };

        if let Message::DataMessage {
            data: Data::Event(event),
            ..
        } = msg
        {
            if event.name != "ping" {
                continue;
            }

            socket
                .send(
                    Message::new_data("/ping", Event::new("pong", vec!["yeah"]))
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
        }
    }
}
