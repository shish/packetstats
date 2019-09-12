packetstats
===========

```
-i --interface
-s --socket    - UNIX socket to write to (else, stdout)
```

```
root@netpi:~# packetstats -i eth0
packetstats,interface=eth0,address=chai,counter=recv,protocol=tcp,port=8086 value=871
packetstats,interface=eth0,address=Muha,counter=recv,protocol=tcp,port=22067 value=4
packetstats,interface=eth0,address=shish2k-mbp,counter=send,protocol=udp,port=8001 value=3
```
