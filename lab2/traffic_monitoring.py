#!/usr/bin/python3

# Import the appropriate libraries
from bcc import BPF
from pyroute2 import IPRoute

import argparse
import time
import socket
import sys

BPF_SOURCE_FILE = 'traffic_monitoring.c'
ETHTYPE_2_PROTO = {
    socket.ntohs(0x0800): 'IPv4',
    socket.ntohs(0x0806): 'ARP',
    socket.ntohs(0x86dd): 'IPv6'
}

if __name__ == "__main__":

    # Parse the command line arguments
    parser = argparse.ArgumentParser('Simple traffic monitoring')
    parser.add_argument('interface', help='Network interface to monitor')
    args = parser.parse_args()

    # Load the eBPF program and get the map
    # More in details:
    # The first instruction load the C source code from specified file
    # The second retrieves a handle to access the content of the hash 
    # map we defined in the eBPF program.
    # The third takes care of validating and compiling the eBPF code.
    # More in detail,
    # the first parameter represents the name of the function to be loaded, 
    # while the latter is a flag defining
    # the type of eBPF program.
    bpf = BPF(src_file=BPF_SOURCE_FILE)
    l3protos_counter = bpf.get_table("l3protos_counter")
    fn = bpf.load_func("monitor", BPF.SCHED_CLS)

    ip = IPRoute()
    ifname = args.interface
    try:
        # Lookup the network interface and get its index
        ifindex = ip.link_lookup(ifname=ifname)[0]
    except IndexError:
        print(f"Interface {ifname} does not exist")
        sys.exit(1)

    # Attach the appropriate qdisc to the selected interface
    ip.tc("add", "clsact", ifindex)

    try:
        # Attach the eBPF program to the interface (ingress)
        ip.tc("add-filter", "bpf", ifindex, ":1", fd=fn.fd, name=fn.name,
            parent="ffff:fff2", classid=1, direct_action=True)
        
        # Attach the eBPF program to the interface (egress)
        ip.tc("add-filter", "bpf", ifindex, ":1", fd=fn.fd, name=fn.name,
            parent="ffff:fff3", classid=1, direct_action=True)
        
        print("Monitoring traffic, hit CTRL+C to stop")
        # Start polling and printing the content of the map
        while True:
            try:
                time.sleep(1)

                print(time.strftime('\n%H.%M.%S:'))

                # Iterate over the entries of the map
                for key, value in l3protos_counter.items():
                    # Retrieve the name of the protocol
                    proto = ETHTYPE_2_PROTO.get(
                        key.value, f'Unknown (0x{socket.htons(key.value):04x})')
                    # Print the content of the value
                    print(f'* {value.count:6d} packets - {value.bytes:10d} bytes for protocol {proto}')
            except KeyboardInterrupt:
                print("Removing filter from device")
                break
    finally:
        # Clean-up the environment
        ip.tc("del", "clsact", ifindex)
