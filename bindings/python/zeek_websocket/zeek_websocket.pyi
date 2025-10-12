import datetime
from collections.abc import Mapping, Sequence
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, TypeAlias, TypeVar

class Event:
    def __init__(
        self,
        name: str,
        args: Sequence[_BrokerSupported],
        metadata: Sequence[_BrokerSupported],
    ): ...
    def serialize_json(self) -> str:
        """Serialize to Zeek WebSocket JSON format."""
        ...

    @staticmethod
    def deserialize_json(value: str) -> Event:
        """Deserialize from Zeek WebSocket JSON format."""
        ...

    name: str
    args: list[Value]
    metadata: list[Value]

_Address: TypeAlias = IPv4Address | IPv6Address | str

_Vector: TypeAlias = list[_BrokerSupported] | Sequence[_BrokerSupported]

_Set: TypeAlias = set[_BrokerSupported] | Sequence[_BrokerSupported]

_Dict: TypeAlias = (
    dict[_BrokerSupported, _BrokerSupported]
    | Mapping[_BrokerSupported, _BrokerSupported]
)

T = TypeVar("T")

_BrokerSupportedNoUserClass: TypeAlias = (
    bool
    | int
    | float
    | datetime.datetime
    | datetime.timedelta
    | _Address
    | tuple[int | Protocol]
    | _Vector
    | _Set
    | _Dict
    | str
    | None
    | Value
)

_BrokerSupported: TypeAlias = _BrokerSupportedNoUserClass | Any

def make_value(data: _BrokerSupported) -> Value:
    """Construct a new value and infers its type.

    This often does the right thing, but the mapping from Python types to Zeek
    WebSocket values is not unambiguous, e.g., a Zeek `Count` and `Integer`
    both map onto Python `int` instances. Use constructors of concrete types
    instead, e.g., `Value.Count` and `Value.Integer`.
    """
    ...

class Value:
    """Zeek WebSocket API representation of Python values.

    A Python representation of the `Value` can be accessed via to `value`
    attribute, e.g., for a `Value.Count` this would hold a Python `int`. For
    the container types `Value.Vector`, `Value.Set` and `Value.Table` it is a
    native Python container value holding `Value` instances, e.g.,

        x = Value.Vector[1, 2]
        x.value == [Value.Count(1), Value.Count(2)]

    Instances of `Value.Enum` hold a Python `str`, and `Value.Record` a Python
    `dict[str, Value]`; use `as_enum` and `as_record` to create native Python
    instances.

    Attributes:
        value: A Python value corresponding to the `Value`.

    """

    value: _BrokerSupportedNoUserClass

    class Address(Value):
        def __init__(self, data: _Address) -> None: ...

    class Boolean(Value):
        def __init__(self, data: bool) -> None: ...

    class Count(Value):
        def __init__(self, data: int) -> None: ...

    class Enum(Value):
        def __init__(self, data: str) -> None: ...

    class Integer(Value):
        def __init__(self, data: int) -> None: ...

    class None_(Value):
        def __init__(self) -> None: ...

    class Port(Value):
        def __init__(self, num: int, proto: Protocol) -> None: ...

    class Real(Value):
        def __init__(self, data: float) -> None: ...

    class Set(Value):
        def __init__(self, data: _Set) -> None: ...

    class String(Value):
        def __init__(self, data: str) -> None: ...

    class Subnet(Value):
        def __init__(self, ip: _Address, prefix: int) -> None: ...

    class Table(Value):
        def __init__(self, data: _Dict) -> None: ...

    class Timespan(Value):
        def __init__(self, data: datetime.timedelta) -> None: ...

    class Timestamp(Value):
        def __init__(self, data: datetime.datetime) -> None: ...

    class Vector(Value):
        def __init__(self, data: _Vector) -> None: ...

    class Record(Value):
        def __init__(self, data: Mapping[str, _BrokerSupported]) -> None: ...

    def serialize_json(self) -> str:
        """Serialize to Zeek WebSocket JSON format."""
        ...

    @staticmethod
    def deserialize_json(value: str) -> Value:
        """Deserialize from Zeek WebSocket JSON format."""
        ...

    def as_enum(self, type_: type[T]) -> T | None:
        """Convert to a given target enum instance.

        `T` must refer to a class which derives from `enum.Enum` or similar.
        """
        ...

    def as_record(self, type_: type[T]) -> T | None:
        """Convert a given target class instance.

        `T` must be a dataclass.
        """
        ...

class Protocol(Enum):
    UNKNOWN = 1
    TCP = 2
    UDP = 3
    ICMP = 4

class ProtocolBinding:
    def __init__(self, topics: Sequence[str]) -> None: ...
    def outgoing(self) -> bytes | None: ...
    def handle_incoming(self, data: bytes) -> None: ...
    def publish_event(self, topic: str, event: Event) -> None: ...
    def receive_event(self) -> tuple[str, Event] | None: ...
