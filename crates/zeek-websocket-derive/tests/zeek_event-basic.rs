use zeek_websocket_derive::zeek_event;

#[zeek_event(handle_foo0)]
fn foo0() {}

#[zeek_event(handle_foo1)]
fn foo1(_a: u8) {}

#[zeek_event(handle_foo2)]
fn foo2(_a: u8, _b: u8) {}

fn main() {}
