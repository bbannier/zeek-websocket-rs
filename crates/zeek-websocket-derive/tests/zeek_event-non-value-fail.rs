use zeek_websocket_derive::zeek_event;

#[zeek_event(handle_foo)]
fn foo(_xs: &u8) {}

fn main() {}
