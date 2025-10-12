from zeek_websocket import Event, Value, make_value


def test_real() -> None:
    json = '{"@data-type":"real","data":123.0}'
    value = Value.Real(123)

    assert value.serialize_json() == json
    assert Value.deserialize_json(json) == make_value(123.0)


def test_none() -> None:
    assert Value.None_().serialize_json() == '{"@data-type":"none"}'


def test_record() -> None:
    from dataclasses import dataclass

    @dataclass
    class X:
        a: float
        b: str

    json = '{"@data-type":"vector","data":[{"@data-type":"real","data":1.0},{"@data-type":"string","data":"2"}]}'

    x = X(1, "2")
    assert make_value(x).serialize_json() == json


def test_event() -> None:
    json = '{"@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"count","data":1},{"@data-type":"vector","data":[{"@data-type":"string","data":"evt"},{"@data-type":"vector","data":[{"@data-type":"real","data":1.0},{"@data-type":"string","data":"str"},{"@data-type":"real","data":2.0}]},{"@data-type":"vector","data":[{"@data-type":"string","data":"meta1"},{"@data-type":"string","data":"meta2"}]}]}]}'
    event = Event("evt", [1, "str", 2], ["meta1", "meta2"])
    assert (
        str(event)
        == 'Event { name: "evt", args: [Real(1.0), String("str"), Real(2.0)], metadata: [String("meta1"), String("meta2")] }'
    )

    assert event.serialize_json() == json
    assert Event.deserialize_json(json) == event
