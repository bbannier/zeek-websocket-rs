use tungstenite::connect;
use zeek_websocket::{
    types::Value,
    {Data, Event, Message, Subscriptions},
};

fn main() {
    let uri = "ws://127.0.0.1:8080/v1/messages/json";

    let (mut socket, _) = connect(uri).unwrap();

    // Subscribe client.
    let subscriptions = Subscriptions(vec!["/ping".into()]);
    socket.send(subscriptions.try_into().unwrap()).unwrap();

    // Write event.
    socket
        .send(
            Message::DataMessage {
                topic: "/ping".into(),
                data: Data::Event(Event {
                    name: "ping".into(),
                    args: vec![Value::String("hohi".into())],
                    metadata: vec![],
                }),
            }
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
                    Message::DataMessage {
                        topic: "/ping".into(),
                        data: Data::Event(Event {
                            name: "pong".into(),
                            args: vec![Value::String("yeah".into())],
                            metadata: vec![],
                        }),
                    }
                    .try_into()
                    .unwrap(),
                )
                .unwrap();
        }
    }
}
