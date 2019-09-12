extern crate argparse;
extern crate etherparse;
extern crate pcap;
use etherparse::*;

use argparse::{ArgumentParser, Store, StoreOption};  // , StoreTrue};
use dns_lookup::lookup_addr;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::IpAddr;
use std::os::unix::net::UnixDatagram;
use std::time::Instant;

fn main() {
    let mut device: String = "eth0".to_string();
    let mut socket: Option<String> = None;
    {
        let mut parser = ArgumentParser::new();
        parser.set_description("Get network stats");
        parser.refer(&mut device).add_option(
            &["-i", "--interface"],
            Store,
            "Device to sniff packets from",
        );
        parser.refer(&mut socket).add_option(
            &["-s", "--socket"],
            StoreOption,
            "UNIX socket to write stats to in influx format",
        );
        parser.parse_args_or_exit();
    }

    let mut cap = Capture::from_device(Device {
        name: device.clone(),
        desc: None,
    })
    .unwrap()
    .open()
    .unwrap();

    run_capture(&device, &mut cap, &socket);
}

fn run_capture(
    device: &String,
    cap: &mut pcap::Capture<pcap::Active>,
    socket: &Option<String>,
) {
    let mut resolv: HashMap<IpAddr, String> = HashMap::new();
    let mut hosts: HashMap<String, u64> = HashMap::new();
    let mut now = Instant::now();
	let freq = 10;
    let my_mac = [0xDC, 0xA6, 0x32, 0x09, 0xA8, 0x88]; // /sys/class/net/eth0/address

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
				if !resolv.contains_key(&remote_ip) {
					resolv.insert(remote_ip, lookup_addr(&remote_ip).unwrap());
				}
				let remote_name = resolv.get(&remote_ip).unwrap();
                let (proto, port) = match value.transport {
                    Some(Udp(value)) => (
                        "udp",
                        if out {
                            value.source_port()
                        } else {
                            value.destination_port()
                        },
                    ),
                    Some(Tcp(value)) => (
                        "tcp",
                        if out {
                            value.source_port()
                        } else {
                            value.destination_port()
                        },
                    ),
                    None => continue,
                };

				let dir = if out {"send"} else {"recv"};

                let connection = format!("address={},counter={},protocol={},port={}", remote_name, dir, proto, port).to_string();

                // increment sent or received hashmap
				*hosts.entry(connection).or_insert(0) += packet_len;

                if now.elapsed().as_secs() > freq {
                    now = Instant::now();
					for (key, value) in &hosts {
						let line = format!(
							"packetstats,interface={},{} value={}",
							device,
							key,
							value / freq
						);
						match socket {
							Some(socket) => {
								let s = UnixDatagram::unbound().unwrap();
								s.send_to(line.as_bytes(), socket).unwrap();
							},
							None => println!("{}", line)
						}
					}
					hosts.clear()
                }
            }
        }
    }
}
