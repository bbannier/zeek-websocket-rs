from collections.abc import Generator
from typing import Any, NoReturn

import pytest
import requests
from fastapi import FastAPI, WebSocket
from zeek_websocket import Client, Event, ProtocolBinding

MOCK_SERVER = FastAPI()


@MOCK_SERVER.websocket("/v1/messages/json")
async def mock_endpoint(websocket: WebSocket) -> NoReturn:
    await websocket.accept()
    import json

    while True:
        x = json.loads((await websocket.receive_bytes()).decode())

        match x:
            case list():
                # If the client sent a list it is subscribing. Respond with an
                # ACK and if there were any subscriptions a single `ping` event
                # on the first subscribed topic.
                await websocket.send_json(
                    {
                        "type": "ack",
                        "endpoint": "925c9110-5b87-57d9-9d80-b65568e87a44",
                        "version": "2.2.0-22",
                    }
                )
                if len(x) > 0:
                    topic = x[0]
                    await websocket.send_json(
                        {
                            "type": "data-message",
                            "topic": topic,
                            "@data-type": "vector",
                            "data": [
                                {"@data-type": "count", "data": 1},
                                {"@data-type": "count", "data": 1},
                                {
                                    "@data-type": "vector",
                                    "data": [
                                        {"@data-type": "string", "data": "ping"},
                                        {"@data-type": "vector", "data": []},
                                    ],
                                },
                            ],
                        }
                    )

            case dict():
                # If the client sent a dict it published an event. Simply echo it back.
                await websocket.send_text(json.dumps(x))


@MOCK_SERVER.get("/health")
async def health() -> bool:
    return True


@pytest.fixture(scope="session")
def mock_server() -> Generator[str, Any, None]:
    import uvicorn

    TEST_HOST = "127.0.0.1"
    TEST_PORT = 8000
    SERVER_URL = f"{TEST_HOST}:{TEST_PORT}"

    config = uvicorn.Config(
        MOCK_SERVER, host=TEST_HOST, port=TEST_PORT, log_level="info"
    )
    server = uvicorn.Server(config)

    def run_server() -> None:
        server.run()

    import threading

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait for the server to start up.
    retries = 5
    for i in range(retries):
        try:
            requests.get(f"http://{SERVER_URL}/health")  # Try a simple endpoint
            print(f"\nServer started on {SERVER_URL}")
            break
        except:
            import time

            time.sleep(1)
    else:
        raise RuntimeError("mock server failed to start within the given timeout.")

    yield f"ws://{SERVER_URL}/v1/messages/json"

    server.should_exit = True
    server_thread.join(timeout=5)


def test_basic_flow() -> None:
    conn = ProtocolBinding([])

    # We subscribed to no topics, so expect an empty subscription message.
    assert conn.outgoing() == b"[]"
    # There should not be any additional messages enqueued.
    assert conn.outgoing() == None

    # Publish an event which should cause it to appear in the outbox.
    event = Event("my_event", (1, "2"), ())
    conn.publish_event("/topic", event)
    serialized_event = b'{"type":"data-message","topic":"/topic","@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"count","data":1},{"@data-type":"vector","data":[{"@data-type":"string","data":"my_event"},{"@data-type":"vector","data":[{"@data-type":"real","data":1.0},{"@data-type":"string","data":"2"}]},{"@data-type":"vector","data":[]}]}]}'
    assert conn.outgoing() == serialized_event

    # Feed an event, we should then be able to receive it.
    assert conn.receive_event() == None
    conn.handle_incoming(serialized_event)
    assert conn.receive_event() == ("/topic", event)


def test_client(mock_server: str) -> None:
    TOPIC = "/topic1"
    client = Client("client", mock_server, [TOPIC])

    # By default the mock responds with a single ping event.
    recv = client.receive()
    assert recv
    topic, ping = recv
    assert topic == TOPIC
    assert ping == Event("ping", (), ())
    with pytest.raises(TimeoutError):
        client.receive(timeout=0.1)

    # For any event published the server simply echos it back to us.
    my_event = Event("ping", (), ())
    client.publish(TOPIC, my_event)
    assert client.receive() == (TOPIC, my_event)
