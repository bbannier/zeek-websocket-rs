use std::collections::BTreeSet;
use zeek_websocket_derive::ZeekType;

#[derive(ZeekType)]
struct X {
    xs: BTreeSet<u8>,
}

fn main() {}
