"""Example async client."""

import asyncio

from zeek_websocket import Event, Service, ZeekClient

NUM_EVENTS = 10

PING = Event("ping", ["hi"], [])


class Client(ZeekClient):
    """Adapted client for the Zeek WebSocket API."""

    async def connected(self, ack: dict[str, str]) -> None:
        """Handle subscription ACK."""
        print(ack)

        # Publish a ping to initiate the ping/pong loop below.
        await self.publish("/ping", PING)

    async def event(self, topic: str, event: Event) -> None:
        """Handle event."""
        global NUM_EVENTS, PING

        print(f"received on '{topic}': {event}")

        if NUM_EVENTS > 0:
            # Publish up to `NUM_EVENTS` ping events.
            await self.publish("/ping", PING)
            NUM_EVENTS -= 1
        else:
            # When we are done disconnect.
            self.disconnect()

    async def error(self, error: str) -> None:
        """Handle error."""
        print(f"received error: {error}")

        # Treat any error as fatal and immediately disconnect.
        self.disconnect()


async def main() -> None:
    """Run the client."""
    await Service.run(
        Client(), "example_client", "ws://localhost:8080/v1/messages/json", ["/ping"]
    )


if __name__ == "__main__":
    asyncio.run(main())
