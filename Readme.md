Speed comparison
----------------

Pcap contains 148652 pings. Only use metadata to calculate time differences
between two adjacent packets.

```
Report
------

PyPacker:     0.14732563914731145s
DPKT:         0.5213165380991995s
PyShark       210.6932880920358s
PyShark fast: 203.81540737696923s
scapy raw:    0.37894420395605266s
scapy:        6.771591873839498s
```