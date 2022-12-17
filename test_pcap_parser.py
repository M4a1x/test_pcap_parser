import timeit
from datetime import timedelta

import dpkt
import pyshark
from pypacker import ppcap
from scapy.config import conf
from scapy.layers.inet import ICMP, IP, Ether
from scapy.utils import PcapReader, RawPcapReader

conf.layers.filter([])
Ether.payload_guess = [({"type": 0x800}, IP)]
IP.payload_guess = [({"proto": 0x01}, ICMP)]


def pairs(items):
    items_iter = iter(items)
    prev = next(items_iter)

    for item in items_iter:
        yield prev, item
        prev = item


def test_scapy_raw():
    for pkt1, pkt2 in pairs(RawPcapReader("receive.pcap")):
        t1 = pkt1[1].sec * 1_000_000 + pkt1[1].usec
        t2 = pkt2[1].sec * 1_000_000 + pkt2[1].usec
        dt = t2 - t1
        if dt > 900_000:
            print(f"({t1},{t2},{dt})")


def test_scapy():
    for pkt1, pkt2 in pairs(PcapReader("receive.pcap")):
        dt = pkt2.time - pkt1.time
        if dt > 0.9:
            print(f"({pkt1.time},{pkt2.time},{dt})")


def test_pyshark():
    cap = pyshark.FileCapture("receive.pcap")
    delta = timedelta(milliseconds=900)
    for pkt1, pkt2 in pairs(cap):
        dt = pkt2.sniff_time - pkt1.sniff_time
        if dt > delta:
            print(f"({pkt1.sniff_time},{pkt2.sniff_time},{dt})")


def test_pyshark_fast():
    cap = pyshark.FileCapture(
        "receive.pcap", keep_packets=False, disable_protocol="Ethernet"
    )
    delta = timedelta(milliseconds=900)
    for pkt1, pkt2 in pairs(cap):
        dt = pkt2.sniff_time - pkt1.sniff_time
        if dt > delta:
            print(f"({pkt1.sniff_timestamp},{pkt2.sniff_timestamp},{dt})")


def test_dpkt():
    f = open("receive.pcap", "rb")
    pcap = dpkt.pcap.Reader(f)
    for (ts1, _buf), (ts2, _buf2) in pairs(pcap):
        dt = ts2 - ts1
        if dt > 0.9:
            print(f"({ts1},{ts2},{dt})")
    f.close()


def test_pypacker():
    preader = ppcap.Reader(filename="receive.pcap")
    for (ts1, _buf1), (ts2, _buf2) in pairs(preader):
        dt = ts2 - ts1
        if dt > 900_000:
            print(f"({ts1},{ts2},{dt})")


if __name__ == "__main__":
    pypacker_t = timeit.timeit("test_pypacker()", globals=globals(), number=1)
    dpkt_t = timeit.timeit("test_dpkt()", globals=globals(), number=1)
    pyshark_fast_t = timeit.timeit("test_pyshark_fast()", globals=globals(), number=1)
    pyshark_t = timeit.timeit("test_pyshark()", globals=globals(), number=1)
    scapy_raw_t = timeit.timeit("test_scapy_raw()", globals=globals(), number=1)
    scapy_t = timeit.timeit("test_scapy()", globals=globals(), number=1)

    print("Report")
    print("------")
    print(f"PyPacker:     {pypacker_t}s")
    print(f"DPKT:         {dpkt_t}s")
    print(f"PyShark       {pyshark_t}s")
    print(f"PyShark fast: {pyshark_fast_t}s")
    print(f"scapy raw:    {scapy_raw_t}s")
    print(f"scapy:        {scapy_t}s")
