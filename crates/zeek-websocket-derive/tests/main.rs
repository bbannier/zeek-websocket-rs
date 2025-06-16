#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/basic.rs");
    t.compile_fail("tests/unit-struct-fail.rs");
    t.compile_fail("tests/tuple-struct-fail.rs");
    t.compile_fail("tests/enum-fail.rs");
    t.compile_fail("tests/unhandled-field-type-fail.rs");

    t.pass("tests/zeek_event-basic.rs");
    t.compile_fail("tests/zeek_event-non-value-fail.rs");
}
