extern crate argparse;
extern crate etherparse;
extern crate pcap;
use etherparse::*;

use argparse::{ArgumentParser, Store, StoreFalse, StoreTrue};
use dns_lookup::lookup_addr;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::net::IpAddr;
use std::time::Instant;

fn main() {
    let mut device: String = "eth0".to_string();
    let mut names: bool = true;
    let mut server: bool = false;
    {
        let mut parser = ArgumentParser::new();
        parser.set_description("Get network stats");
        parser.refer(&mut device).add_option(
            &["-i", "--interface"],
            Store,
            "Device to sniff packets from",
        );
        parser.refer(&mut names).add_option(
            &["-n", "--no-names"],
            StoreFalse,
            "Don't convert IP addresses to names",
        );
        parser.refer(&mut server).add_option(
            &["-s", "--server"],
            StoreTrue,
            "Record the local port numbers (default: assume we are a client \
            and record the remote port numbers)",
        );
        parser.parse_args_or_exit();
    }

    run_capture(&device, names, server);
}

fn get_mac(device: &String) -> [u8; 6] {
    let data: String = fs::read_to_string(format!("/sys/class/net/{}/address", device))
        .expect("Unable to read file");
    let bytes_vec: Vec<&str> = data.trim().split(":").collect();
    let bytes_arr: [&str; 6] = bytes_vec[0..6]
        .try_into()
        .expect("slice with incorrect length");
    return [
        u8::from_str_radix(bytes_arr[0], 16).unwrap(),
        u8::from_str_radix(bytes_arr[1], 16).unwrap(),
        u8::from_str_radix(bytes_arr[2], 16).unwrap(),
        u8::from_str_radix(bytes_arr[3], 16).unwrap(),
        u8::from_str_radix(bytes_arr[4], 16).unwrap(),
        u8::from_str_radix(bytes_arr[5], 16).unwrap(),
    ];
}

fn run_capture(device: &String, names: bool, server: bool) {
    let mut resolv: HashMap<IpAddr, String> = HashMap::new();
    let mut hosts: HashMap<String, u64> = HashMap::new();
    let mut now = Instant::now();
    let freq = 10;
    let my_mac = get_mac(device);
    let mut cap = Capture::from_device(Device {
        name: device.clone(),
        desc: None,
    })
    .unwrap()
    .open()
    .unwrap();
    let mut last_stats = cap.stats().unwrap();

    while let Ok(packet) = cap.next() {
        let sliced_packet = SlicedPacket::from_ethernet(&packet.data);
        match sliced_packet {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                use crate::InternetSlice::*;
                use crate::LinkSlice::*;
                use crate::TransportSlice::*;

                // Figure out if this packet is being sent or received
                let out = match value.link {
                    Some(Ethernet2(value)) => value.source() == my_mac,
                    None => {
                        continue;
                    }
                };

                // Get remote address and packet length in a v4/v6-neutral way
                let (remote_ip, packet_len) = match value.ip {
                    Some(Ipv4(value)) => (
                        IpAddr::V4(if out {
                            value.destination_addr()
                        } else {
                            value.source_addr()
                        }),
                        value.to_header().total_len() as u64,
                    ),
                    Some(Ipv6(value, _)) => (
                        IpAddr::V6(if out {
                            value.destination_addr()
                        } else {
                            value.source_addr()
                        }),
                        value.to_header().payload_length as u64,
                    ),
                    None => {
                        continue;
                    }
                };

                // Get a connection name
                let remote_ip_str;
                let remote_name = if names {
                    if !resolv.contains_key(&remote_ip) {
                        resolv.insert(remote_ip, lookup_addr(&remote_ip).unwrap());
                    }
                    resolv.get(&remote_ip).unwrap()
                } else {
                    remote_ip_str = remote_ip.to_string();
                    &remote_ip_str
                };
                let (proto, port) = match value.transport {
                    Some(Udp(value)) => (
                        "udp",
                        if server == out {
                            value.source_port()
                        } else {
                            value.destination_port()
                        },
                    ),
                    Some(Tcp(value)) => (
                        "tcp",
                        if server == out {
                            value.source_port()
                        } else {
                            value.destination_port()
                        },
                    ),
                    None => continue,
                };

                let dir = if out { "send" } else { "recv" };

                let connection = format!(
                    "address={},counter={},protocol={},port={}",
                    remote_name, dir, proto, port
                )
                .to_string();

                // increment sent or received hashmap
                *hosts.entry(connection).or_insert(0) += packet_len;

                if now.elapsed().as_secs() > freq {
                    now = Instant::now();
                    for (key, value) in &hosts {
                        println!(
                            "packetstats,interface={},{} value={}",
                            device,
                            key,
                            value / freq
                        );
                    }
                    let stats = cap.stats().unwrap();
                    println!(
                        "packetstats_meta,interface={} received={},dropped={},if_dropped={}",
                        device,
                        (stats.received - last_stats.received) / freq as u32,
                        (stats.dropped - last_stats.dropped) / freq as u32,
                        (stats.if_dropped - last_stats.if_dropped) / freq as u32
                    );
                    last_stats = stats;
                    hosts.clear();
                    resolv.clear();
                }
            }
        }
    }
}
