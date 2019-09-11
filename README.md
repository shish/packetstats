packetstats
===========

```
-i --interface
-s --socket    - UNIX socket to write to (else, stdout)
```

```
$ packetstats -i eth0
packetstats,counter=send,interface=eth0 192.168.4.3,tcp,80=1234
packetstats,counter=recv,interface=eth0 192.168.4.3,tcp,80=5678
```
