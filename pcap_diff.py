#!/usr/bin/python3
#
# Diff two or more pcap files and write a pcap file with different packets as result
#
#
# You need to install scapy to use this script
# -> pip install scapy-python3
#
# Copyright 2013-2018 ETH Zurich, ISGINF, Bastian Ballmann
# E-Mail: bastian.ballmann@inf.ethz.ch
# Web: http://www.isg.inf.ethz.ch
#
# This is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# It is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License.
# If not, see <http://www.gnu.org/licenses/>.


###[ Loading modules ]###

import sys
import getopt
import re
from scapy.all import PcapReader, wrpcap, Packet, NoPayload

###[ Parsing parameter ]###

output_file       = None
input_files       = []
complete_diff     = False
ignore_source     = False
ignore_source_ip  = False
ignore_dest_ip    = False
ignore_source_mac = False
ignore_macs       = False
ignore_seq_ack    = False
ignore_ip_id      = False
ignore_timestamp  = False
ignore_ttl        = False
ignore_ck         = False
ignore_headers    = []
first_layer       = None
diff_only_left    = False
diff_only_right   = False
be_quiet          = False
show_diffs        = False

def usage():
    print(sys.argv[0])
    print("""
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Diff two or more pcap files
    Programmed by Bastian Ballmann <bastian.ballmann@inf.ethz.ch>
    Version 1.3.0
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

    -i <input_file>  (use multiple times)
    -o <output_file> (this is a pcap file)
    -c (complete diff, dont ignore ttl, checksums and timestamps) - False by default
    -l     diff only left side (first pcap file)
    -L <scapy_layer_name> ignores everything below the given layer
    -r     diff only right side (not first pcap file)
    -f s   (ignore src ip / mac)
    -f sm  (ignore src mac)
    -f si  (ignore src ip)
    -f di  (ignore dst ip)
    -f m   (ignore mac addresses)
    -f sa  (ignore tcp seq and ack num)
    -f ii  (ignore ip id)
    -f ts  (ignore timestamp)
    -f ttl (ignore ttl)
    -f ck  (ignore checksum)
    -f <scapy header name>
    -q     be quiet
    -d     show differences

    Example usage with ignore mac addresses
    pcap_diff.py -i client.dump -i server.dump -o diff.pcap -f m

    """)
    sys.exit(1)

try:
    cmd_opts = "cf:i:L:lo:qrd"
    opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
    usage()

for opt in opts:
    if opt[0] == "-i":
        input_files.append(opt[1])
    elif opt[0] == "-o":
        output_file = opt[1]
    elif opt[0] == "-c":
        complete_diff = True
    elif opt[0] == "-d":
        show_diffs = True
    elif opt[0] == "-l":
        diff_only_left = True
    elif opt[0] == "-L":
        first_layer = opt[1]
    elif opt[0] == "-r":
        diff_only_right = True
    elif opt[0] == "-q":
        be_quiet = True
    elif opt[0] == "-f":
        if opt[1] == "s":
            ignore_source = True
        elif opt[1] == "sm":
            ignore_source_mac = True
        elif opt[1] == "sa":
            ignore_seq_ack = True
        elif opt[1] == "ii":
            ignore_ip_id = True
            ignore_ck  = True
        elif opt[1] == "si":
            ignore_source_ip = True
        elif opt[1] == "di":
            ignore_dest_ip = True
        elif opt[1] == "m":
            ignore_macs = True
        elif opt[1] == "ts":
            ignore_timestamp = True
        elif opt[1] == "ttl":
            ignore_ttl = True
            ignore_ck  = True
        elif opt[1] == "ck":
            ignore_ck = True
        else:
            ignore_headers.append(opt[1])
    else:
        usage()

if len(input_files) < 2:
   print("Need at least 2 input files to diff")
   sys.exit(1)


###[ Subroutines ]###


def serialize(packet):
    """
    Serialize flattened packet
    """

    result = packet.show(dump = True)
    if ignore_macs:
        result = re.split(r'###\[ IP \]###', result)[1]
    if ignore_ttl:
        result = re.sub(r'\s+ttl\s+=\s+\d+', '', result)
    if ignore_ck:
        result = re.sub(r'\s+chksum\s+=\s+\S+', '', result)

    return result


def read_dump(pcap_file):
    """
    Read PCAP file
    Return dict of packets with serialized flat packet as key
    """
    dump = {}
    count = 0

    if not be_quiet:
        sys.stdout.write("Reading file " + pcap_file + ":\n")
        sys.stdout.flush()

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            count += 1
            dump[serialize(packet)] = packet

    if not be_quiet:
        sys.stdout.write("Found " + str(count) + " packets\n\n")
        sys.stdout.flush()

    return dump

def compare_summary ():
    ret = ""
    if complete_diff:
        ret += "Complete, "
    if ignore_source:
        ret += "no src mac, no src ip, "
    if ignore_source_mac:
        ret += "no src mac, "
    if ignore_source_ip:
        ret += "no src ip, "
    if ignore_dest_ip:
        ret += "no dst ip, "
    if ignore_seq_ack:
        ret += "not seq ack, "
    if ignore_ip_id:
        ret += "no ip id, "
    if ignore_ttl:
        ret += "no ttl, "
    if ignore_ck:
        ret += "no checksum, "
    if ignore_timestamp:
        ret += "no timestamp, "
    for h in ignore_headers:
        ret += "no " + h + ", "

    return ret

###[ MAIN PART ]###

# Parse pcap files
dumps = []

for input_file in input_files:
    dumps.append(read_dump(input_file))

# Diff the dumps
diff_counter = 0
diff_packets = []
base_dump = dumps.pop(0)

if not be_quiet:
    print("Diffing packets: " + compare_summary())

for packet in base_dump.values():
    serial_packet = serialize(packet)
    found_packet = False

    for dump in dumps:
        if dump.get(serial_packet):
            del dump[serial_packet]
            found_packet = True

    if not diff_only_right and not found_packet:
        if show_diffs:
            print(" <<< " + packet.summary())
        diff_packets.append(packet)

if not diff_only_left:
    for dump in dumps:
        if len(dump.values()) > 0:
            diff_packets.extend(dump.values())

            if show_diffs:
                for packet in dump.values():
                    print(" >>> " + packet.summary())

if not be_quiet:
    print("\nFound " + str(len(diff_packets)) + " different packets\n")

# Write pcap diff file?
if output_file and diff_packets:
    if not be_quiet:
        print("Writing " + output_file)
    wrpcap(output_file, diff_packets)

    sys.exit(len(diff_packets))
else:
    sys.exit(0)
