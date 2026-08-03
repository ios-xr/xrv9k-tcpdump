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
"""Unit tests for xrv9k_pcap_decode.decode_packet and parse_iface_map.

Frames are synthesised in-memory: each test builds the outer Ethernet+IPv4+UDP
wrapper, an 82-byte punt/inject header with the fields needed for that path,
optional feature header, and an inner payload, then asserts the decoded
direction, handle, and SLL-wrapped EPB data.
"""

import struct

import pytest

from xrv9k_pcap_decode import (
    ETH_P_802_2,
    ETH_P_ARP,
    ETH_P_IPV4,
    ETH_P_IPV6,
    HEADER_MAGIC,
    ISIS_LLC_PREFIX,
    MSG_TYPE_INJECT,
    MSG_TYPE_PUNT,
    SLL_HOST,
    SLL_OUTGOING,
    SkipPacket,
    decode_packet,
    parse_iface_map,
)


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------

def _outer(udp_dst_port=9911, udp_payload=b"", outer_etype=0x0800, ip_proto=17):
    """Build Ethernet(14) + IPv4(20) + UDP(8) + payload."""
    eth = b"\xff" * 6 + b"\x11" * 6 + struct.pack(">H", outer_etype)
    ip_total_len = 20 + 8 + len(udp_payload)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", ip_total_len)
        + b"\x00\x00\x00\x00\x40"
        + bytes([ip_proto])
        + b"\x00\x00"
        + b"\x01\x02\x03\x04"
        + b"\x05\x06\x07\x08"
    )
    udp = (
        b"\x00\x01"
        + struct.pack(">H", udp_dst_port)
        + struct.pack(">H", 8 + len(udp_payload))
        + b"\x00\x00"
    )
    return eth + ip + udp + udp_payload


def _punt_inject_header(
    msg_type,
    *,
    feature_hdr_len=0,
    pkt_type=0,
    input_if_handle=0,
    output_if_handle=0,
    magic=HEADER_MAGIC,
):
    """Build the fixed 82-byte punt/inject base header with the fields we exercise."""
    hdr = bytearray(82)
    hdr[0:4] = magic
    hdr[4:8] = struct.pack("<I", msg_type)
    hdr[46:50] = struct.pack("<I", input_if_handle)
    hdr[54] = feature_hdr_len
    hdr[55] = pkt_type
    hdr[70:74] = struct.pack("<I", output_if_handle)
    return bytes(hdr)


def _frame(msg_type, inner=b"", *, feature_hdr=b"", **hdr_kwargs):
    payload = _punt_inject_header(msg_type, feature_hdr_len=len(feature_hdr), **hdr_kwargs)
    payload += feature_hdr + inner
    return _outer(udp_payload=payload)


# Useful fixture inner frames
ETH_II_IPV4 = (
    b"\xaa" * 6                   # dst MAC
    + b"\xbb" * 6                 # src MAC (will appear in SLL header for PUNT)
    + b"\x08\x00"                 # EtherType IPv4
    + b"\x45\x00\x00\x14" + b"\x00" * 16  # minimal IPv4 header
)

ETH_8023_ISIS = (
    b"\x01\x80\xc2\x00\x00\x15"   # IS-IS L2 multicast dst
    + b"\xcc" * 6                 # src MAC
    + b"\x00\x40"                 # 802.3 length field (< 0x0600)
    + b"\xfe\xfe\x03"             # LLC: DSAP, SSAP, Control
    + b"\x83" + b"\x00" * 30      # IS-IS PDU starting with 0x83
)


# ---------------------------------------------------------------------------
# Happy paths — one per dispatch branch
# ---------------------------------------------------------------------------

def test_punt_ethernet_ii_ipv4():
    frame = _frame(MSG_TYPE_PUNT, ETH_II_IPV4, input_if_handle=0x01000018)
    direction, handle, epb, pkt_type = decode_packet(frame)
    assert direction == "punt"
    assert handle == 0x01000018
    assert pkt_type is None
    # SLL: packet_type=HOST, ARPHRD=1, addr_len=6, src=bb*6, pad, proto=IPv4
    assert epb[:2] == struct.pack(">H", SLL_HOST)
    assert epb[6:12] == b"\xbb" * 6
    assert epb[14:16] == struct.pack(">H", ETH_P_IPV4)
    # Payload after SLL is the inner Ethernet payload (after the 14-byte header)
    assert epb[16:] == ETH_II_IPV4[14:]


def test_punt_8023_isis_uses_llc_protocol_code():
    frame = _frame(MSG_TYPE_PUNT, ETH_8023_ISIS, input_if_handle=0x42)
    direction, handle, epb, _ = decode_packet(frame)
    assert direction == "punt"
    assert handle == 0x42
    assert epb[14:16] == struct.pack(">H", ETH_P_802_2)
    # 802.3 path keeps the LLC bytes in the payload
    assert epb[16:19] == b"\xfe\xfe\x03"


@pytest.mark.parametrize("pkt_type", [1, 7, 9, 12])
def test_inject_ipv4_pkt_types(pkt_type):
    inner = b"\x45\x00\x00\x14" + b"\x00" * 16  # raw IPv4 datagram
    frame = _frame(MSG_TYPE_INJECT, inner, pkt_type=pkt_type, output_if_handle=0xdeadbeef)
    direction, handle, epb, got_pkt_type = decode_packet(frame)
    assert direction == "inject"
    assert handle == 0xdeadbeef
    assert got_pkt_type == pkt_type
    assert epb[:2] == struct.pack(">H", SLL_OUTGOING)
    assert epb[6:14] == b"\x00" * 8       # zero src address
    assert epb[14:16] == struct.pack(">H", ETH_P_IPV4)
    assert epb[16:] == inner


@pytest.mark.parametrize("pkt_type", [2, 13])
def test_inject_ipv6_pkt_types(pkt_type):
    inner = b"\x60" + b"\x00" * 39        # minimal IPv6 header, version=6
    frame = _frame(MSG_TYPE_INJECT, inner, pkt_type=pkt_type)
    _, _, epb, _ = decode_packet(frame)
    assert epb[14:16] == struct.pack(">H", ETH_P_IPV6)
    assert epb[16:] == inner


def test_inject_isis_prepends_llc():
    inner = b"\x83\x1b\x01\x00" + b"\x00" * 16   # IS-IS PDU starting with 0x83
    frame = _frame(MSG_TYPE_INJECT, inner, pkt_type=4, feature_hdr=b"\x00" * 32)
    _, _, epb, _ = decode_packet(frame)
    assert epb[14:16] == struct.pack(">H", ETH_P_802_2)
    assert epb[16:19] == ISIS_LLC_PREFIX
    assert epb[19:] == inner


def test_inject_l2_arp_signature():
    arp = b"\x00\x01\x08\x00" + b"\x06\x04\x00\x01" + b"\x00" * 20
    frame = _frame(MSG_TYPE_INJECT, arp, pkt_type=36)
    _, _, epb, _ = decode_packet(frame)
    assert epb[14:16] == struct.pack(">H", ETH_P_ARP)
    assert epb[16:] == arp


def test_feature_header_offsets_inner_payload():
    inner = b"\x45\x00\x00\x14" + b"\x00" * 16
    feature = b"\xff" * 32
    frame = _frame(MSG_TYPE_INJECT, inner, pkt_type=1, feature_hdr=feature)
    _, _, epb, _ = decode_packet(frame)
    # Inner IPv4 must come through untouched after the feature-header skip.
    assert epb[16:] == inner


# ---------------------------------------------------------------------------
# Skip paths
# ---------------------------------------------------------------------------

def test_skip_non_ipv4_outer():
    with pytest.raises(SkipPacket, match="non-IPv4"):
        decode_packet(_outer(outer_etype=0x86DD))


def test_skip_non_udp():
    with pytest.raises(SkipPacket, match="non-UDP"):
        decode_packet(_outer(ip_proto=6, udp_payload=b"\x00" * 90))


def test_skip_wrong_port():
    with pytest.raises(SkipPacket, match="unexpected UDP port"):
        decode_packet(_outer(udp_dst_port=4444, udp_payload=b"\x00" * 90))


def test_skip_no_magic():
    bad = _frame(MSG_TYPE_PUNT, ETH_II_IPV4, magic=b"\x00\x00\x00\x00")
    with pytest.raises(SkipPacket, match="header magic not found"):
        decode_packet(bad)


def test_skip_unknown_msg_type():
    with pytest.raises(SkipPacket, match="unknown message type"):
        decode_packet(_frame(0xff, ETH_II_IPV4))


def test_skip_unknown_inject_pkt_type():
    inner = b"\x00" * 30
    frame = _frame(MSG_TYPE_INJECT, inner, pkt_type=99)
    with pytest.raises(SkipPacket, match="unrecognised INJECT pkt_type"):
        decode_packet(frame)


def test_skip_unknown_l2_inject_payload():
    not_arp = b"\xde\xad\xbe\xef" + b"\x00" * 20
    frame = _frame(MSG_TYPE_INJECT, not_arp, pkt_type=36)
    with pytest.raises(SkipPacket, match="unrecognised L2 INJECT payload"):
        decode_packet(frame)


def test_skip_truncated_short_outer():
    # Less than even the outer Ethernet header.
    with pytest.raises(SkipPacket, match="truncated"):
        decode_packet(b"\x00" * 10)


def test_skip_truncated_no_room_for_header():
    # Valid outer headers but UDP payload < 82 bytes.
    with pytest.raises(SkipPacket, match="truncated"):
        decode_packet(_outer(udp_payload=b"\x00" * 10))


# ---------------------------------------------------------------------------
# parse_iface_map
# ---------------------------------------------------------------------------

def test_parse_iface_map(tmp_path):
    f = tmp_path / "ifh.txt"
    f.write_text(
        "Header line that should be ignored\n"
        "Interface GigabitEthernet0/0/0/0, ifh 0x01000018, type 0x14, ...\n"
        "garbage line\n"
        "Interface TenGigE0/0/0/1.100, ifh 0x0a000028, type 0x14, ...\n"
    )
    mapping = parse_iface_map(str(f))
    assert mapping == {
        0x01000018: "GigabitEthernet0/0/0/0",
        0x0a000028: "TenGigE0/0/0/1.100",
    }
