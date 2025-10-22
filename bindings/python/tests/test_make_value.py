import dataclasses
import enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address

import pytest
from zeek_websocket import Protocol, Value, make_value


def test_address() -> None:
    x = make_value(IPv4Address("127.0.0.1"))
    assert isinstance(x, Value.Address)
    assert x.value == IPv4Address("127.0.0.1")

    x = make_value("127.0.0.1")
    assert isinstance(x, Value.Address)
    assert x.value == IPv4Address("127.0.0.1")


def test_bool() -> None:
    x = make_value(True)
    assert isinstance(x, Value.Boolean)
    assert x.value == True  # noqa: E712


def test_count() -> None:
    x = make_value(123)
    assert isinstance(x, Value.Count)
    assert x.value == 123


def test_enum() -> None:
    class E(enum.Enum):
        a = 1
        b = 2

    e_a = Value.Enum("a")
    assert str(e_a) == 'Enum("a")'

    assert e_a.value == "a"
    assert e_a.as_enum(E) == E.a

    with pytest.raises(KeyError) as err:
        Value.Enum("bogus_string").as_enum(E)
    assert str(err.value) == "'bogus_string'"


def test_integer() -> None:
    x = make_value(-123)
    assert isinstance(x, Value.Integer)
    assert x.value == -123


def test_protocol() -> None:
    x = make_value((8080, Protocol.TCP))
    assert isinstance(x, Value.Port)
    assert x.value == (8080, Protocol.TCP)


def test_real() -> None:
    x = make_value(0.5)
    assert isinstance(x, Value.Real)
    assert x.value == 0.5


def test_set() -> None:
    x = make_value({1, 2, 3})
    assert isinstance(x, Value.Set)
    assert x.value == {Value.Count(i) for i in [1, 2, 3]}

    x = Value.Set({Value.Count(1), Value.Count(2), Value.Count(3)})
    assert str(x) == "Set({Count(1), Count(2), Count(3)})"


def test_string() -> None:
    x = make_value("abc")
    assert isinstance(x, Value.String)
    assert x.value == "abc"


def test_subnet() -> None:
    x = make_value(("127.0.0.1", 8))
    assert isinstance(x, Value.Subnet)
    assert x.value == (IPv4Address("127.0.0.1"), 8)


def test_table() -> None:
    x = make_value({"1": 11, "2": 22, "3": 33})
    assert isinstance(x, Value.Table)
    assert x.value == {
        Value.String(k): Value.Count(v)
        for (k, v) in {"1": 11, "2": 22, "3": 33}.items()
    }

    x = Value.Table(
        {
            Value.Count(1): Value.String("11"),
            Value.Count(2): Value.String("22"),
            Value.Count(3): Value.String("33"),
        }
    )
    assert (
        str(x)
        == 'Table({Count(1): String("11"), Count(2): String("22"), Count(3): String("33")})'
    )


def test_timespan() -> None:
    x = make_value(timedelta(seconds=42))
    assert isinstance(x, Value.Timespan)
    assert x.value == timedelta(seconds=42)


def test_timestamp() -> None:
    x = make_value(datetime(year=2000, month=1, day=2))
    assert isinstance(x, Value.Timestamp)
    assert x.value == datetime(year=2000, month=1, day=2)


def test_vector() -> None:
    x = make_value([1, 2, 3])
    assert isinstance(x, Value.Vector)
    assert x.value == [Value.Count(i) for i in [1, 2, 3]]

    x = Value.Vector([Value.Count(1), Value.Count(2), Value.Count(3)])
    assert str(x) == "Vector([Count(1), Count(2), Count(3)])"


def test_record_dataclass() -> None:
    @dataclass
    class X:
        a: int
        b: str

    x = X(1, "2")
    value = make_value(x)
    assert str(value) == 'Record({"a": Count(1), "b": String("2")})'
    assert Value.Record(dataclasses.asdict(x)) == value

    assert value.value == {"a": Value.Count(1), "b": Value.String("2")}
    x2 = value.as_record(X)
    assert x2 == X(1, "2")


def test_vector_as_record() -> None:
    @dataclass
    class X:
        a: int
        b: str

    value = Value.Vector([1, "2"])
    assert value.as_record(X) == X(1, "2")


def test_record_other() -> None:
    class Y:
        c: int
        d: str

    y = Y()
    y.c = 1
    y.d = "2"
    value = make_value(y)
    assert type(value) is Value.Record
    assert str(value) == 'Record({"c": Count(1), "d": String("2")})'

    assert value.value == {"c": Value.Count(1), "d": Value.String("2")}
    with pytest.raises(RuntimeError) as err:
        value.as_record(Y)
    assert (
        str(err.value)
        == "<class 'test_make_value.test_record_other.<locals>.Y'> is not a dataclass"
    )


def test_str() -> None:
    assert str(Value.Boolean(True)) == "Boolean(true)"
    assert str(Value.Boolean(False)) == "Boolean(false)"

    assert str(Value.Count(123)) == "Count(123)"
    assert str(Value.Integer(123)) == "Integer(123)"

    assert str(Value.Port(8080, Protocol.TCP)) == "Port(8080, TCP)"
    assert str(Value.Port(8080, Protocol.UDP)) == "Port(8080, UDP)"
    assert str(Value.Port(8080, Protocol.ICMP)) == "Port(8080, ICMP)"
    assert str(Value.Port(8080, Protocol.UNKNOWN)) == "Port(8080, UNKNOWN)"

    assert str(Value.Real(0.5)) == "Real(0.5)"
    assert str(Value.Address("127.0.0.1")) == "Address(127.0.0.1)"
    assert str(Value.Subnet("127.0.0.1", 8)) == "Subnet(127.0.0.1, 8)"
    assert (
        str(Value.Timespan(timedelta(seconds=0.5)))
        == "Timespan(TimeDelta { secs: 0, nanos: 500000000 })"
    )
    assert (
        str(Value.Timestamp(datetime(2000, 10, 2))) == "Timestamp(2000-10-02T00:00:00)"
    )
    assert str(Value.None_()) == "None_"
    assert str(Value.String("abc")) == 'String("abc")'
    assert str(Value.Enum("abc")) == 'Enum("abc")'
    assert str(Value.Vector([1, 2, 3])) == "Vector([Count(1), Count(2), Count(3)])"
    assert str(Value.Set({1, 2, 3})) == "Set({Count(1), Count(2), Count(3)})"

    assert (
        str(Value.Table({"a": 1, "b": 2, "c": 3}))
        == 'Table({String("a"): Count(1), String("b"): Count(2), String("c"): Count(3)})'
    )
