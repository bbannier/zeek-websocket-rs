from zeek_websocket import Event, Value, make_value


def test_count() -> None:
    json = '{"@data-type":"count","data":123}'
    value = Value.Count(123)

    assert value.serialize_json() == json
    assert Value.deserialize_json(json) == make_value(123)


def test_none() -> None:
    assert Value.None_().serialize_json() == '{"@data-type":"none"}'


def test_record() -> None:
    from dataclasses import dataclass

    @dataclass
    class X:
        a: int
        b: str

    json = '{"@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"string","data":"2"}]}'

    x = X(1, "2")
    assert make_value(x).serialize_json() == json


def test_event() -> None:
    json = '{"@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"count","data":1},{"@data-type":"vector","data":[{"@data-type":"string","data":"evt"},{"@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"string","data":"str"},{"@data-type":"count","data":2}]},{"@data-type":"vector","data":[{"@data-type":"string","data":"meta1"},{"@data-type":"string","data":"meta2"}]}]}]}'
    event = Event("evt", [1, "str", 2], ["meta1", "meta2"])

    assert event.serialize_json() == json
    assert Event.deserialize_json(json) == event
