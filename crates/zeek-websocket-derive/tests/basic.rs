use zeek_websocket_derive::ZeekType;

#[derive(ZeekType)]
struct A {
    x: u8,
    y: u8,
    z: u8,
}

#[derive(ZeekType)]
struct B {}

#[derive(ZeekType)]
struct C {
    x: u8,
    y: Option<u8>,
}

fn main() {}
