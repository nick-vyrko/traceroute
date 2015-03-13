import argparse
import socket
import time

import const

def main():
    parser = argparse.ArgumentParser(description="Starting traceroute")
    parser.add_argument('address', help='destination address of traceroute')
    parser.add_argument('-s', '--size', help='set the packet size')
    parser.add_argument('-pc', '--packetcount', help='set the count of sending packets')
    parser.add_argument('-hops', help='set max hops')
    args = parser.parse_args()

    dest_addr = socket.gethostbyname(args.address)
    packet_size = args.size if args.size else const.PACKET_SIZE
    packet_count = args.packetcount if args.packetcount else const.PACKET_COUNT
    max_hops = args.hops if args.hops else const.MAX_HOPS
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        recieve_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error:
        print "cant create socket"
        return
    recieve_sock.bind(('', const.PORT))
    recieve_sock.settimeout(2)
    ttl = 1
    print "\ntraceroute to {0} ({1}), {2} hops max, {3} bytes packets\n".format(args.address,
                                                                            dest_addr,
                                                                            max_hops,
                                                                            packet_size)
    while True:
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        curr_addr = None
        curr_name = None
        each_time = []
        ttl += 1
        for i in xrange(packet_count):
            send_sock.sendto("Z"*packet_size, (dest_addr, const.PORT))
            each_time.append(time.time())

        try:
            for i in xrange(packet_count):
                _, curr_addr = recieve_sock.recvfrom(512)
                each_time[i] = (time.time() - each_time[i])*1000
            curr_addr = curr_addr[0]
            try:
                curr_name = socket.gethostbyaddr(curr_addr)
                curr_name = curr_name[0]
            except socket.error:
                curr_name = curr_addr
        except socket.timeout:
            curr_host = '*'
            curr_addr = None

        if curr_addr is not None:
            curr_host = "%-30s (%-15s)" % (curr_name, curr_addr)
            for i in each_time:
                curr_host += " %-0.3f ms " % (i,)
        else:
            curr_host = '*'
        print "%2d %s" % (ttl-1, curr_host)

        if curr_addr == dest_addr or ttl == max_hops:
            send_sock.close()
            recieve_sock.close()
            break


if __name__ == "__main__":
    main()
