"""Python bindings for Zeek's WebSocket API.

The Zeek-side API wrapped here is
[here](https://docs.zeek.org/projects/broker/en/current/web-socket.html#data-representation).

See the module stub file for documentation for the provided functionality.
"""

from .zeek_websocket import *  # noqa: F403
from .zeek_websocket import Event, ProtocolBinding

__doc__ = zeek_websocket.__doc__  # type: ignore[name-defined] # noqa: F405
if hasattr(zeek_websocket, "__all__"):  # type: ignore[name-defined] # noqa: F405
    __all__ = zeek_websocket.__all__  # type: ignore[name-defined] # noqa: F405


from collections.abc import Sequence

import websockets.sync.client


class Client:
    """Client for the Zeek WebSocket API."""

    _binding: ProtocolBinding
    _conn: websockets.sync.client.ClientConnection

    def __init__(self, app_name: str, endpoint_uri: str, topics: Sequence[str]) -> None:
        """Create a client instance.

        Args:
            app_name: Identifier for this client. Zeek uses this for logging and metrics.
            endpoint_uri: Zeek endpoint to connect to. This needs to be a full
                          URI including protocol (ws or wss), hostname, and path, e.g.,
                          `ws://localhost:8080/v1/messages/json`.
            topics: Zero or more topics to subscribe to.

        """
        self._binding = ProtocolBinding(topics)

        self._conn = websockets.sync.client.connect(
            endpoint_uri, additional_headers={"X-Application-Name": app_name}
        )

    def publish(self, topic: str, event: Event) -> None:
        """Publish an event on a give topic."""
        self._binding.publish_event(topic, event)

        self._flush()

    def receive(self) -> tuple[str, Event] | None:
        """Try to receive the next event, returns the topic and the event, or None."""
        self._flush()

        return self._binding.receive_event()

    def _flush(self) -> None:
        # Flush all outgoing messages.
        while data := self._binding.outgoing():
            self._conn.send(data)

        # Forward all messages received over the WebSocket connection to our internal handling.
        while True:
            try:
                data = self._conn.recv(decode=False, timeout=0.001)
                self._binding.handle_incoming(data)
            except TimeoutError:
                break
