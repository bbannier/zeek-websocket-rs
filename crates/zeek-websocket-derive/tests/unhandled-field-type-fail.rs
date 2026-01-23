use zeek_websocket_derive::ZeekType;

struct Custom;

#[derive(ZeekType)]
struct X {
    xs: Custom,
}

fn main() {}
