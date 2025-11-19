#!/usr/bin/env zeek

# Starts a 0mq-backed Zeek cluster listening on 8080 for WebSocket traffic.

@load frameworks/cluster/backend/zeromq/connect

redef Cluster::Backend::ZeroMQ::run_proxy_thread = T;

const TOPIC = "/ping";

global ping: event(msg: string) &is_used;
global pong: event(msg: string) &is_used;

event ping(msg: string)
	{
	local evt = Cluster::make_event(pong, "ho!");
	print "sending pong";
	Cluster::publish(TOPIC, evt);
	}

event zeek_init()
	{
	Cluster::listen_websocket([$listen_addr=127.0.0.1, $listen_port=8080/tcp]);
	Cluster::subscribe(TOPIC);
	}

##########################################
# LOGGING
##########################################
event Cluster::Backend::ZeroMQ::hello(name: string, id: string)
	{
	print "hello", name, id;
	}

event Cluster::Backend::ZeroMQ::subscription(topic: string)
	{
	print "subscription", topic;
	}

event Cluster::node_up(name: string, id: string)
	{
	print "node_up", name, string;
	}
