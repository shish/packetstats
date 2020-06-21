packetstats
===========

Keep track of which TCP / UDP ports are seeing most traffic. Works on clients,
servers, and routers (Allowing you to see which clients on your LAN are
generating the most traffic, using which protocols; or which servers are
being downloaded from the most).

My original use-case was using a raspberry pi as a router with two USB 4G
dongles as upstream connections - I wanted to figure out the main bandwidth
hogs to send them over the cheap connection, and leave the rest on the fast
connection.

`packetstats` numbers are bytes-per-second, `packetstats_meta` numbers are
packets-per-second.

Options:
```
-i --interface     which network interface to listen to
-n --no-names      don't do reverse dns lookups
-s --server        record incoming ports rather than outgoing
```

Example:
```
root@netpi:~# packetstats -i eth0
packetstats,interface=eth0,address=chai,counter=recv,protocol=tcp,port=8086 value=871
packetstats,interface=eth0,address=Muha,counter=recv,protocol=tcp,port=22067 value=4
packetstats,interface=eth0,address=shish2k-mbp,counter=send,protocol=udp,port=8001 value=3
packetstats_meta,interface=eth0 received=1,dropped=0,if_dropped=0
```

Build:
```
# apt install libpcap-dev
$ cargo build
```

Recommended use with telegraf: add to `/etc/telegraf/telegraf.d/packetstats.conf`
```
[[inputs.execd]]
command = ["sudo", "/usr/local/bin/packetstats", "-i", "eth0"]
signal = "none"
restart_delay = "10s"
data_format = "influx"
```
