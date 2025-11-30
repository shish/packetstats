use etherparse::*;

use anyhow::{anyhow, Result};
use clap::Parser;
use dns_lookup::lookup_addr;
use pcap::{Capture, Device, Packet};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::net::IpAddr;
use std::time::Instant;

/// Get network stats
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Device to sniff packets from
    #[arg(short = 'i', long = "interface")]
    interface: Option<String>,

    /// Don't convert IP addresses to names
    #[arg(short = 'n', long = "no-names", default_value_t = false)]
    no_names: bool,

    /// Record the local port numbers (default: assume we are a client and record the remote port numbers)
    #[arg(short = 's', long = "server", default_value_t = false)]
    server: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let device = match args.interface {
        Some(dev) => dev,
        None => {
            Device::lookup()?
                .ok_or(anyhow!("Unable to find device"))?
                .name
        }
    };
    let names = !args.no_names;
    let server = args.server;

    run_capture(&device, names, server)?;

    Ok(())
}

fn get_mac(device: &String) -> Result<[u8; 6]> {
    let data: String = fs::read_to_string(format!("/sys/class/net/{}/address", device))?;
    let bytes_vec: Vec<&str> = data.trim().split(":").collect();
    let bytes_arr: [&str; 6] = bytes_vec[0..6].try_into()?;
    Ok([
        u8::from_str_radix(bytes_arr[0], 16)?,
        u8::from_str_radix(bytes_arr[1], 16)?,
        u8::from_str_radix(bytes_arr[2], 16)?,
        u8::from_str_radix(bytes_arr[3], 16)?,
        u8::from_str_radix(bytes_arr[4], 16)?,
        u8::from_str_radix(bytes_arr[5], 16)?,
    ])
}

fn run_capture(device: &String, names: bool, server: bool) -> Result<()> {
    let mut resolv: HashMap<IpAddr, String> = HashMap::new();
    let mut hosts: HashMap<String, u64> = HashMap::new();
    let mut now = Instant::now();
    let freq = 10;
    let my_mac = get_mac(device)?;
    let dev = Device::list()?
        .iter()
        .find(|d| d.name == *device)
        .ok_or(anyhow!("Can't find device '{}'", device))?
        .clone();
    let mut cap = Capture::from_device(dev)?.open()?;
    let mut last_stats = cap.stats()?;

    loop {
        if let Some((remote_name, out, proto, port, packet_len)) =
            parse_packet(cap.next_packet()?, my_mac, names, server, &mut resolv)?
        {
            let dir = if out { "send" } else { "recv" };

            let connection = format!(
                "address={},counter={},protocol={},port={}",
                remote_name, dir, proto, port
            )
            .to_string();

            // increment sent or received hashmap
            *hosts.entry(connection).or_insert(0) += packet_len;
        }

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
            let stats = cap.stats()?;
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

type PacketData = (String, bool, String, u16, u64);

/**
 * Parse an ethernet + IP + TCP/UDP packet and return stats about it.
 * Returns None if the packet is not ethernet / not IP / etc.
 */
fn parse_packet(
    raw_packet: Packet,
    my_mac: [u8; 6],
    names: bool,
    server: bool,
    resolv: &mut HashMap<IpAddr, String>,
) -> Result<Option<PacketData>> {
    use crate::InternetSlice::*;
    use crate::LinkSlice::*;
    use crate::TransportSlice::*;

    let packet = SlicedPacket::from_ethernet(raw_packet.data)?;

    // Figure out if this packet is being sent or received
    let out = match packet.link {
        Some(Ethernet2(value)) => value.source() == my_mac,
        _ => return Ok(None),
    };

    // Get remote address and packet length in a v4/v6-neutral way
    let (remote_ip, packet_len) = match packet.net {
        Some(Ipv4(value)) => (
            IpAddr::V4(if out {
                value.header().destination_addr()
            } else {
                value.header().source_addr()
            }),
            value.header().total_len() as u64,
        ),
        Some(Ipv6(value)) => (
            IpAddr::V6(if out {
                value.header().destination_addr()
            } else {
                value.header().source_addr()
            }),
            value.header().payload_length() as u64,
        ),
        _ => return Ok(None),
    };

    // Get a connection name
    let remote_ip_str;
    let remote_name = if names {
        resolv
            .entry(remote_ip)
            .or_insert_with(|| lookup_addr(&remote_ip).unwrap_or(remote_ip.to_string()))
    } else {
        remote_ip_str = remote_ip.to_string();
        &remote_ip_str
    };
    let (proto, port) = match packet.transport {
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
        _ => return Ok(None),
    };

    Ok(Some((
        remote_name.to_string(),
        out,
        proto.to_string(),
        port,
        packet_len,
    )))
}
