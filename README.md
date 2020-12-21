# vinbero

## Setup
```
ulimit -l unlimited

# if "ulimit -l unlimited" is not working when plz check
# https://bbs.archlinux.org/viewtopic.php?pid=1828148#p1828148
# echo "DefaultLimitMEMLOCK=infinity">>/etc/systemd/system.conf
# echo "DefaultLimitMEMLOCK=infinity">>/etc/systemd/user.conf
```

remove offload
```
for i in rx tx tso ufo gso gro lro tx nocache copy sg txvlan rxvlan; do
       /sbin/ethtool -K eth2 $i off 2>&1 > /dev/null;
done
```

## Build
```
cd include
wget https://raw.githubusercontent.com/cloudflare/xdpcap/master/hook.h
# todo: use pushd/pop shellsctipt
cd ..
go get -u github.com/rakyll/statik
```

## xdpcap

See https://github.com/cloudflare/xdpcap

```
# run on each nodes
sudo mount bpffs /sys/fs/bpf -t bpf

# capture packets
xdpcap /sys/fs/bpf/xdpcap_hook "icmp"
```

## tips
### debug
```
sudo trace-cmd record -e 'xdp:*' -O trace_printk
sudo trace-cmd report > trace.log
```

## List of SRv6 functions of interest and status (a.k.a. Road Map)

### Reference list
* [draft-murakami-dmm-user-plane-message-encoding-02](https://datatracker.ietf.org/doc/draft-murakami-dmm-user-plane-message-encoding)

* [draft-filsfils-spring-srv6-network-programming-27]https://datatracker.ietf.org/doc/draft-ietf-spring-srv6-network-programming/)

### Transit behaviors

| Function | schedule | description |
|----------|----------|-------------|
| T | n/a | Transit behavior|
| T.Insert | Fed, 2020 | |
| T.Insert.Red | future | |
| T.Encaps | future | |
| T.Encaps.Red | future | |
| T.Encaps.L2 | future | |
| T.Encaps.L2.Red | future | |

### Functions associated with a SID

| Function | schedule | description |
|----------|----------|-------------|
| End | Done | |
| End.X | Fed, 2020 | |
| End.T | | |
| End.DX2 (V) | | |
| End.DT2 (U/M) | | |
| End.DX6 | | |
| End.DX4 | | |
| End.DT6 | | |
| End.DT4 | | |
| End.DT46 | | |
| End.B6.Insert | | |
| End.B6.Insert.Red | | |
| End.B6.Encaps | | |
| End.B6.Encaps.Red | | |
| End.BM | | |
| End.S | | |
| Args.Mob.Session | | Consider with End.MAP, End.DT and End.DX |
| End.MAP | | |
| End.M.GTP6.D | Jan, 2021 | GTP-U/IPv6 => SRv6 |
| End.M.GTP6.D.Di | Jan, 2021 | GTP-U/IPv6 => SRv6 |
| End.M.GTP6.E | Jan, 2021 | SRv6 => GTP-U/IPv6 |
| End.M.GTP4.D | Jan, 2021 | SRv6 => GTP-U/IPv4 |
| End.M.GTP4.E | Jan, 2021 | GTP-U/IPv4 => SRv6 |
| T.M.GTP4.D | Jan, 2021 | GTP-U/IPv4 => SRv6 |
| End.Limit | | Rate Limiting function |

### Non functional design items

| Item name | schedule |
|-----------|----------|
| BSID friendly table structure | future |

### Flavours

| Function | schedule | description |
|----------|----------|-------------|
| PSP | future | Penultimate Segment Pop |
| USP | | Ultimate Segment Pop |
| USD | | Ultimate Segment Decapsulation |

