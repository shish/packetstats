packetstats
===========

Options:
```
-i --interface     which network interface to listen to
-n --no-names      don't do reverse dns lookups
```

Example:
```
root@netpi:~# packetstats -i eth0
packetstats,interface=eth0,address=chai,counter=recv,protocol=tcp,port=8086 value=871
packetstats,interface=eth0,address=Muha,counter=recv,protocol=tcp,port=22067 value=4
packetstats,interface=eth0,address=shish2k-mbp,counter=send,protocol=udp,port=8001 value=3
```

Recommended use with telegraf: add to `/etc/telegraf/telegraf.d/packetstats.conf`
```
[[inputs.execd]]
command = ["sudo", "/usr/local/bin/packetstats", "-i", "eth0"]
signal = "none"
restart_delay = "10s"
data_format = "influx"
```
