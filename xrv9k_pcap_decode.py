#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Decode an XRv9K tcpdump punt/inject capture into a standard pcapng file.

XRv9K carries its internal control-plane (punt/inject) traffic as UDP
datagrams wrapped in a proprietary header. A raw ``tcpdump`` capture of that
traffic is therefore not directly readable by Wireshark. This tool strips the
wrapper and re-emits each frame as a DLT_LINUX_SLL packet in a pcapng file,
grouped per interface, so any standard packet analyser can decode it.

See the README for capture instructions and usage.
"""

import argparse
import os
import re
import struct
import sys
from collections import OrderedDict, defaultdict


# ---------------------------------------------------------------------------
# punt/inject framing (operational summary)
# ---------------------------------------------------------------------------
#
# XRv9K control-plane traffic is punted (rx) and injected (tx) as UDP
# datagrams on an internal IPC interface. Each UDP payload begins with a fixed
# 82-byte proprietary header, optionally followed by a variable feature
# header, then the actual protocol packet.
#
# This tool decodes only the few header fields it needs:
#   - a 4-byte magic that marks one of these datagrams,
#   - a message-type field giving direction (PUNT = rx, INJECT = tx),
#   - interface-handle fields used to group packets per interface,
#   - a feature-header length, and (for INJECT) a packet-type field used to
#     identify the inner protocol.
#
# Both PUNT and INJECT traffic share the same UDP ports; direction comes from
# the message-type field, not the port. The port set below is only a coarse
# "is this punt/inject traffic?" filter.

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Program name used in diagnostic messages.
PROG = "xrv9k_pcap_decode"

# punt/inject UDP destination ports — used purely as a coarse "is this
# punt/inject traffic?" filter. Direction comes from the msg_type field, not
# the port. BFD traffic (on separate ports) is intentionally excluded; it is
# not decoded.
PUNT_INJECT_PORTS = {9910, 9911, 9912, 9913, 9920, 9921, 9922, 9923}

# header sentinels
HEADER_MAGIC = b"\xab\xcd\x12\x34"   # at offset 0..3 of UDP payload
MSG_TYPE_INJECT = 0x15               # msg_type u32 LE at offset 4..7
MSG_TYPE_PUNT = 0x2a

# INJECT pkt_type dispatch — numeric packet-type codes carried in the header,
# grouped by the inner protocol they deliver.
PKT_TYPE_IPV4 = {1, 7, 9, 12}    # codes observed preceding IPv4 payloads
PKT_TYPE_IPV6 = {2, 13}          # codes observed preceding IPv6 payloads
PKT_TYPE_ISIS = 4                # IS-IS / CLNS
PKT_TYPE_L2 = 36                 # generic L2 (e.g. ARP)

# DLT_LINUX_SLL
SLL_LINKTYPE = 113
SLL_HOST = 0          # rx (PUNT)
SLL_OUTGOING = 4      # tx (INJECT)
SLL_ARPHRD_ETH = 1

ETH_P_802_2 = 0x0004  # IEEE 802.3 LLC framing
ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806

# IS-IS LLC prefix: DSAP=0xFE, SSAP=0xFE, Control=0x03 (UI frame)
ISIS_LLC_PREFIX = b"\xfe\xfe\x03"

# pcapng block types
SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
EPB_TYPE = 0x00000006

SNAPLEN = 65535


# ---------------------------------------------------------------------------
# Legacy pcap reader
# ---------------------------------------------------------------------------

# Standard libpcap microsecond magic written by tcpdump on a little-endian
# host. Big-endian capture hosts and nanosecond-precision pcaps are valid
# libpcap variants but won't appear here: XR is x86 and tcpdump writes
# microseconds by default.
PCAP_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"


class PcapReader:
    """Iterate (ts_sec, ts_us, incl_len, orig_len, data) tuples from a pcap file."""

    def __init__(self, path):
        self._f = open(path, "rb")
        header = self._f.read(24)
        if len(header) < 24:
            raise ValueError("not a valid pcap file (truncated global header)")
        if header[:4] != PCAP_MAGIC_LE_US:
            raise ValueError(
                f"unsupported pcap magic {header[:4].hex()} "
                f"(expected little-endian microsecond pcap)"
            )

    def __iter__(self):
        while True:
            hdr = self._f.read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_us, incl_len, orig_len = struct.unpack("<IIII", hdr)
            data = self._f.read(incl_len)
            if len(data) < incl_len:
                return
            yield ts_sec, ts_us, incl_len, orig_len, data

    def close(self):
        self._f.close()


# ---------------------------------------------------------------------------
# punt/inject decoder
# ---------------------------------------------------------------------------

# Skip categories — keys for the per-reason counter shown in the summary.
SKIP_NON_IPV4 = "non-IPv4 outer frame"
SKIP_NON_UDP = "non-UDP outer frame"
SKIP_WRONG_PORT = "unexpected UDP port"
SKIP_NO_MAGIC = "header magic not found"
SKIP_BAD_MSG_TYPE = "unknown message type"
SKIP_TRUNCATED = "truncated packet"
SKIP_UNKNOWN_INJECT = "unrecognised INJECT pkt_type"
SKIP_UNKNOWN_L2_INJECT = "unrecognised L2 INJECT payload"


class SkipPacket(Exception):
    """Raised by decode_packet to signal a recoverable skip with a reason."""


def _sll_header(packet_type, src_addr, sll_protocol):
    addr_field = src_addr + b"\x00" * (8 - len(src_addr))
    return (
        struct.pack(">HHH", packet_type, SLL_ARPHRD_ETH, len(src_addr))
        + addr_field
        + struct.pack(">H", sll_protocol)
    )


def decode_packet(data):
    """Decode one captured frame.

    Returns ``(direction, handle, epb_data, pkt_type)`` where ``pkt_type`` is
    the INJECT packet-type value for INJECT packets and ``None`` for PUNT.
    Raises ``SkipPacket(reason)`` if the frame is not a decodable punt/inject
    packet.
    """
    if len(data) < 14:
        raise SkipPacket(SKIP_TRUNCATED)
    if struct.unpack(">H", data[12:14])[0] != ETH_P_IPV4:
        raise SkipPacket(SKIP_NON_IPV4)

    if len(data) < 14 + 20:
        raise SkipPacket(SKIP_TRUNCATED)
    ihl = (data[14] & 0x0F) * 4
    if ihl < 20:
        raise SkipPacket(SKIP_TRUNCATED)
    if data[14 + 9] != 17:  # IPv4 protocol field
        raise SkipPacket(SKIP_NON_UDP)

    udp_off = 14 + ihl
    if len(data) < udp_off + 8:
        raise SkipPacket(SKIP_TRUNCATED)
    dst_port = struct.unpack(">H", data[udp_off + 2:udp_off + 4])[0]
    if dst_port not in PUNT_INJECT_PORTS:
        raise SkipPacket(SKIP_WRONG_PORT)

    p = udp_off + 8  # start of the punt/inject header
    if len(data) < p + 82:
        raise SkipPacket(SKIP_TRUNCATED)
    if data[p:p + 4] != HEADER_MAGIC:
        raise SkipPacket(SKIP_NO_MAGIC)
    msg_type = struct.unpack("<I", data[p + 4:p + 8])[0]
    if msg_type == MSG_TYPE_PUNT:
        direction = "punt"
    elif msg_type == MSG_TYPE_INJECT:
        direction = "inject"
    else:
        raise SkipPacket(SKIP_BAD_MSG_TYPE)

    feature_hdr_len = data[p + 54]
    inner_start = p + 82 + feature_hdr_len
    if inner_start >= len(data):
        raise SkipPacket(SKIP_TRUNCATED)
    inner = data[inner_start:]

    if direction == "punt":
        return _decode_punt(data, p, inner)
    return _decode_inject(data, p, inner)


def _is_valid_ifh(h):
    """Return True if h looks like a real XR interface handle.

    Interface handles seen in captures have their high byte in {0x00, 0x01},
    matching the handle values shown by ``show pfi-ifh database``. Some punted
    frames (observed with certain ICMPv6 types) carry an unpopulated input
    handle that fails this check; the caller then falls back to the output
    handle to recover the interface (see _decode_punt).
    """
    return (h >> 24) in (0x00, 0x01)


def _decode_punt(data, p, inner):
    input_ifh  = struct.unpack("<I", data[p + 46:p + 50])[0]
    output_ifh = struct.unpack("<I", data[p + 70:p + 74])[0]
    # Use input_if_handle when it is a valid handle; fall back to
    # output_if_handle for packets where input_if_handle is not populated
    # (ICMPv6 RA/NA frames observed in practice).
    handle = input_ifh if _is_valid_ifh(input_ifh) else output_ifh
    if len(inner) < 14:
        raise SkipPacket(SKIP_TRUNCATED)
    eth_src = inner[6:12]
    etype_field = struct.unpack(">H", inner[12:14])[0]
    payload = inner[14:]
    if etype_field >= 0x0600:
        # Ethernet II — etype_field is the EtherType.
        sll_protocol = etype_field
    else:
        # 802.3 — etype_field is a length; payload includes the LLC bytes
        # which Wireshark's sll dissector hands off to the LLC dissector
        # when sll_protocol == ETH_P_802_2.
        sll_protocol = ETH_P_802_2
    sll = _sll_header(SLL_HOST, eth_src, sll_protocol)
    return "punt", handle, sll + payload, None


def _decode_inject(data, p, inner):
    handle = struct.unpack("<I", data[p + 70:p + 74])[0]
    pkt_type = data[p + 55]
    if pkt_type in PKT_TYPE_IPV4:
        sll_protocol = ETH_P_IPV4
        payload = inner
    elif pkt_type in PKT_TYPE_IPV6:
        sll_protocol = ETH_P_IPV6
        payload = inner
    elif pkt_type == PKT_TYPE_ISIS:
        # Raw IS-IS PDU has no L2 framing; Wireshark's sll->llc->osi chain
        # only fires when both the ETH_P_802_2 protocol code and a real LLC
        # header are present (determined empirically).
        sll_protocol = ETH_P_802_2
        payload = ISIS_LLC_PREFIX + inner
    elif pkt_type == PKT_TYPE_L2:
        # pkt_type 36 is a generic L2 frame; only ARP is identified by signature.
        if inner[:4] == b"\x00\x01\x08\x00":  # HTYPE=Ethernet, PTYPE=IPv4
            sll_protocol = ETH_P_ARP
            payload = inner
        else:
            raise SkipPacket(SKIP_UNKNOWN_L2_INJECT)
    else:
        raise SkipPacket(SKIP_UNKNOWN_INJECT)
    sll = _sll_header(SLL_OUTGOING, b"", sll_protocol)
    return "inject", handle, sll + payload, pkt_type


# ---------------------------------------------------------------------------
# Interface map parser
# ---------------------------------------------------------------------------

_IFACE_PATTERN = re.compile(r"Interface\s+(\S+),\s+ifh\s+(0x[0-9a-fA-F]+)")


def parse_iface_map(path):
    mapping = {}
    with open(path) as f:
        for line in f:
            m = _IFACE_PATTERN.search(line)
            if m:
                mapping[int(m.group(2), 16)] = m.group(1)
    return mapping


# ---------------------------------------------------------------------------
# pcapng writer
# ---------------------------------------------------------------------------

def _pad4(b):
    pad = (-len(b)) % 4
    return b + b"\x00" * pad


def _option(code, value):
    return struct.pack("<HH", code, len(value)) + _pad4(value)


def _block(block_type, body):
    """Wrap a pre-aligned body in block_type / total_length / body / total_length."""
    total = 8 + len(body) + 4
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def shb(comment=None):
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)  # section_length unspecified
    opts = b""
    if comment:
        opts += _option(1, comment.encode("utf-8"))  # opt_comment
    if opts:
        opts += _option(0, b"")  # opt_endofopt
    return _block(SHB_TYPE, body + opts)


def idb(linktype, snaplen, name):
    body = struct.pack("<HHI", linktype, 0, snaplen)
    opts = _option(2, name.encode("utf-8"))   # if_name
    opts += _option(9, b"\x06")               # if_tsresol = 10^-6 (microseconds)
    opts += _option(0, b"")                   # opt_endofopt
    return _block(IDB_TYPE, body + opts)


def epb(interface_id, ts_sec, ts_us, packet):
    ts = ts_sec * 1_000_000 + ts_us
    body = struct.pack(
        "<IIIII",
        interface_id,
        (ts >> 32) & 0xFFFFFFFF,
        ts & 0xFFFFFFFF,
        len(packet),
        len(packet),
    )
    body += _pad4(packet)
    return _block(EPB_TYPE, body)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

HELP_CAPTURE_TEXT = """\
Step 1 — from the router exec prompt, enter the XR Linux shell with 'run':

  RP/0/RP0/CPU0:router# run
  [xr-vm_node0_RP0_CPU0:~]$

Step 2 — collect the capture (in that Linux shell):

  tcpdump -U -i eth-vf1.3074 -w /misc/scratch/capture.pcap udp portrange 9910-9923

  eth-vf1.3074 is the GUEST_CTRL_ETH InternalEther interface.
  portrange 9910-9923 covers all four punt/inject priority queues.

  Stop with Ctrl-C, then copy the file off the router:
    scp router:/misc/scratch/capture.pcap .

Step 3 — collect the interface name mapping. Run this at the XR exec prompt
(type 'exit' to leave the Linux shell first, or use a separate session):

  show pfi-ifh database all location 0/0/CPU0 | include ifh

  Save the output to a text file, e.g. ifh_map.txt.

Step 4 — run the decode tool (on the host where you copied the files):

  python3 xrv9k_pcap_decode.py -m ifh_map.txt capture.pcap
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Decode an XRv9K tcpdump punt/inject capture and write a "
                    "pcapng file.",
    )
    parser.add_argument("input", nargs="?", metavar="INPUT",
                        help="input .pcap file collected from the router")
    parser.add_argument("-m", "--iface-map", metavar="FILE",
                        help="handle-to-name mapping file (see --help-capture)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="output .pcapng file (default: INPUT with .pcapng suffix)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print one line per decoded packet to stderr")
    parser.add_argument("--help-capture", action="store_true",
                        help="print router collection instructions and exit")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.help_capture:
        sys.stdout.write(HELP_CAPTURE_TEXT)
        return 0

    if not args.input:
        print(f"{PROG}: missing INPUT (use --help for usage)", file=sys.stderr)
        return 1

    name_map = {}
    if args.iface_map:
        try:
            name_map = parse_iface_map(args.iface_map)
        except OSError as e:
            print(f"{PROG}: cannot read {args.iface_map}: {e}", file=sys.stderr)
            return 1

    try:
        reader = PcapReader(args.input)
    except (OSError, ValueError) as e:
        print(f"{PROG}: {args.input}: {e}", file=sys.stderr)
        return 1

    # Single-pass decode + buffer; output writes IDBs (from observed handles)
    # ahead of EPBs so the pcapng forward references are satisfied.
    entries = []                 # (ts_sec, ts_us, handle, epb_data)
    handle_order = OrderedDict()  # handle -> {"punt": n, "inject": n}
    skips = defaultdict(int)
    total_read = 0

    try:
        for ts_sec, ts_us, _incl, _orig, data in reader:
            total_read += 1
            try:
                direction, handle, epb_data, pkt_type = decode_packet(data)
            except SkipPacket as e:
                skips[str(e)] += 1
                continue
            counts = handle_order.setdefault(handle, {"punt": 0, "inject": 0})
            counts[direction] += 1
            entries.append((ts_sec, ts_us, handle, epb_data))
            if args.verbose:
                tag = f"pkt_type={pkt_type}" if pkt_type is not None else "eth"
                print(
                    f"{ts_sec}.{ts_us:06d} {direction:6s} ifh={handle:#010x} {tag}",
                    file=sys.stderr,
                )
    finally:
        reader.close()

    if not entries:
        print(f"{PROG}: no decodable packets found in {args.input}", file=sys.stderr)
        return 3

    handle_to_idx = {h: i for i, h in enumerate(handle_order)}
    names = []
    for handle in handle_order:
        if handle in name_map:
            names.append(name_map[handle])
        else:
            fallback = f"if-{handle:#010x}"
            if args.iface_map:
                print(
                    f"warning: no name for handle {handle:#010x} — using {fallback}",
                    file=sys.stderr,
                )
            names.append(fallback)

    out_path = args.output or os.path.splitext(args.input)[0] + ".pcapng"
    try:
        out = open(out_path, "wb")
    except OSError as e:
        print(f"{PROG}: cannot write {out_path}: {e}", file=sys.stderr)
        return 2

    with out:
        out.write(shb(comment=f"{PROG}: {os.path.basename(args.input)}"))
        for name in names:
            out.write(idb(SLL_LINKTYPE, SNAPLEN, name))
        for ts_sec, ts_us, handle, epb_data in entries:
            out.write(epb(handle_to_idx[handle], ts_sec, ts_us, epb_data))

    print(
        f"{PROG}: read {total_read} packets, "
        f"wrote {len(handle_order)} IDBs, {len(entries)} EPBs",
        file=sys.stderr,
    )
    for reason, count in sorted(skips.items()):
        print(f"  skipped: {count:>5}  {reason}", file=sys.stderr)
    name_width = max((len(n) for n in names), default=0)
    for i, (handle, counts) in enumerate(handle_order.items()):
        print(
            f"  IDB {i}  {names[i]:<{name_width}}  "
            f"punt={counts['punt']}  inject={counts['inject']}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
