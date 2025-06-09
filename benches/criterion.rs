use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
};

use chrono::TimeDelta;
use criterion::*;
use ipnetwork::{IpNetwork, Ipv4Network};
use iso8601::DateTime;

use zeek_websocket::{
    Data, Event, Message,
    types::{Port, Protocol, Value},
};

fn serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");
    group.throughput(Throughput::Elements(1));

    group.bench_function("none", |b| {
        b.iter(|| serde_json::to_string(&Value::from(())))
    });
    group.bench_function("bool", |b| {
        b.iter(|| serde_json::to_string(&Value::from(bool::default())))
    });
    group.bench_function("u64", |b| {
        b.iter(|| serde_json::to_string(&Value::from(u64::default())))
    });
    group.bench_function("i64", |b| {
        b.iter(|| serde_json::to_string(&Value::from(i64::default())))
    });
    group.bench_function("f64", |b| {
        b.iter(|| serde_json::to_string(&Value::from(f64::default())))
    });
    group.bench_function("timespan", |b| {
        let timespan = TimeDelta::default();
        b.iter(|| serde_json::to_string(&Value::from(timespan)))
    });
    group.bench_function("timestamp", |b| {
        let timestamp = DateTime::default();
        b.iter(|| serde_json::to_string(&Value::from(timestamp)))
    });
    group.bench_function("string", |b| {
        let string = "";
        b.iter(|| serde_json::to_string(&Value::from(string)))
    });
    group.bench_function("address", |b| {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0));
        b.iter(|| serde_json::to_string(&Value::from(addr)))
    });
    group.bench_function("subnet", |b| {
        let subnet = IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        b.iter(|| serde_json::to_string(&Value::from(subnet)))
    });
    group.bench_function("port", |b| {
        let port = Port::new(8080, Protocol::TCP);
        b.iter(|| serde_json::to_string(&Value::from(port)))
    });
    group.bench_function("vector", |b| {
        b.iter(|| serde_json::to_string(&Value::from(Vec::<bool>::new())))
    });
    group.bench_function("set", |b| {
        b.iter(|| serde_json::to_string(&Value::from(HashSet::<bool>::new())))
    });
    group.bench_function("map", |b| {
        b.iter(|| serde_json::to_string(&Value::from(HashMap::<bool, i64>::new())))
    });

    group.bench_function("event", |b| {
        b.iter(|| Message::new_data("ping", Event::new("ping", vec![1])))
    });

    group.finish();
}

criterion_group!(benches, bench_value, encode_simple_event);
criterion_main!(benches);
