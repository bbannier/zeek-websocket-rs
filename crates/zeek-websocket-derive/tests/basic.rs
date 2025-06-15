use zeek_websocket_derive::ZeekType;
use zeek_websocket_types::Value;

#[derive(ZeekType)]
struct A {
    x: u8,
    y: u8,
    z: u8,
}

#[derive(ZeekType)]
struct B {}

fn main() {
    let a = A { x: 1, y: 2, z: 3 };
    let _v = Value::from(a);

    let b = B {};
    let _v = Value::from(b);
}
