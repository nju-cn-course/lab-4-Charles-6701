import time
import switchyard
from switchyard.lib.userlib import *
from ipaddress import IPv4Network, IPv4Address
from collections import deque

class PendingPacket:
    def __init__(self, packet, next_hop, out_iface, time_sent, retries=0):
        self.packet = packet
        self.next_hop = next_hop
        self.out_iface = out_iface
        self.time_sent = time_sent
        self.retries = retries

class PendingPacketQueue:
    def __init__(self, net):
        self.net = net
        self.queue = deque()
        self.max_retries = 4
        self.retry_interval = 1.0  # 秒

    def add_packet(self, packet, next_hop, out_iface):
        current_time = time.time()
        pending_packet = PendingPacket(packet, next_hop, out_iface, current_time)
        self.queue.append(pending_packet)
        self.send_arp_request(next_hop, out_iface)

    def send_arp_request(self, ip_addr: IPv4Address, out_iface: str):
        interface = self.net.interface_by_name(out_iface)
        arp_request = create_ip_arp_request(interface.ethaddr, interface.ipaddr, ip_addr)
        self.net.send_packet(out_iface, arp_request)
        log_info(f"发送ARP请求以解析IP地址 {ip_addr} 在接口 {out_iface}")

    def process_arp_reply(self, arp, arp_cache, forward_packet_callback):
        arp_cache[arp.senderprotoaddr] = arp.senderhwaddr
        log_info(f"更新ARP缓存: {arp.senderprotoaddr} -> {arp.senderhwaddr}")

        for packet_info in list(self.queue):
            if packet_info.next_hop == arp.senderprotoaddr:
                forward_packet_callback(packet_info.packet, arp.senderhwaddr, packet_info.out_iface)
                self.queue.remove(packet_info)

    def retry_pending_packets(self):
        current_time = time.time()
        for packet_info in list(self.queue):
            if current_time - packet_info.time_sent > self.retry_interval:
                if packet_info.retries < self.max_retries:
                    self.send_arp_request(packet_info.next_hop, packet_info.out_iface)
                    packet_info.retries += 1
                    packet_info.time_sent = current_time
                    log_info(f"重新发送ARP请求以解析 {packet_info.next_hop}，重试次数: {packet_info.retries}")
                else:
                    log_info(f"达到最大重试次数，丢弃数据包，目标地址: {packet_info.next_hop}")
                    self.queue.remove(packet_info)

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.addresses = {}
        self.forwarding_table = []
        self.arp_cache = {}  # ARP缓存表
        self.pending_packets = PendingPacketQueue(net)  # 待处理的 ARP 数据包队列

        # 初始化接口表和直接连接的转发表
        for item in net.interfaces(): 
            self.addresses[item.ipaddr] = {'mac': item.ethaddr, 'iface': item.name}
            network = IPv4Network(f"{item.ipaddr}/{item.netmask}", strict=False)
            self.forwarding_table.append((network.network_address, network.netmask, IPv4Address("0.0.0.0"), item.name))

        self.load_forwarding_table()

    def load_forwarding_table(self):
        """
        从 'forwarding_table.txt' 文件加载转发表
        """
        try:
            with open("forwarding_table.txt", "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    network, netmask, next_hop, interface = line.strip().split()
                    network = IPv4Address(network)
                    netmask = IPv4Address(netmask)
                    next_hop = IPv4Address(next_hop)
                    self.forwarding_table.append((network, netmask, next_hop, interface))
            log_info("成功加载转发表")
        except FileNotFoundError:
            log_error("未找到转发表文件 'forwarding_table.txt'")

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_debug("收到数据包: {}".format(str(packet)))

        ip = packet.get_header(IPv4)
        if ip:
            if ip.dst in self.addresses:
                log_info("数据包目的地是路由器本身，丢弃数据包")
                return

            ip.ttl -= 1  # 减少 TTL 值

            best_match = self.lookup_forwarding_table(ip.dst)
            if best_match is None:
                log_info("未在转发表中找到匹配项，丢弃数据包")
                return
            
            _, _, next_hop, out_iface = best_match
            if next_hop == IPv4Address("0.0.0.0"):
                next_hop = ip.dst

            mac_addr = self.arp_cache.get(next_hop)
            if mac_addr:
                self.forward_packet(packet, mac_addr, out_iface)
            else:
                self.pending_packets.add_packet(packet, next_hop, out_iface)

        arp = packet.get_header(Arp)
        if arp:
            if arp.operation == ArpOperation.Reply:
                self.pending_packets.process_arp_reply(arp, self.arp_cache, self.forward_packet)
            elif arp.operation == ArpOperation.Request and arp.targetprotoaddr in self.addresses:
                self.send_arp_reply(arp, ifaceName)

    def lookup_forwarding_table(self, dest_ip: IPv4Address):
        best_match = None
        longest_prefix = -1
        for network, netmask, next_hop, interface in self.forwarding_table:
            prefix_length = IPv4Network(f"{network}/{netmask}").prefixlen
            if (int(dest_ip) & int(netmask)) == int(network):
                if prefix_length > longest_prefix:
                    best_match = (network, netmask, next_hop, interface)
                    longest_prefix = prefix_length
        return best_match

    def send_arp_reply(self, arp, ifaceName):
        interface = self.net.interface_by_name(ifaceName)
        arp_reply = create_ip_arp_reply(interface.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
        self.net.send_packet(ifaceName, arp_reply)
        log_info(f"发送ARP回复到 {arp.senderprotoaddr}")

    def forward_packet(self, packet, mac_addr, out_iface):
        interface = self.net.interface_by_name(out_iface)
        eth = Ethernet(src=interface.ethaddr, dst=mac_addr, ethertype=EtherType.IP)
        packet[0] = eth
        self.net.send_packet(out_iface, packet)
        log_info(f"转发数据包到 {packet[IPv4].dst} 经由接口 {out_iface}")

    def start(self):
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.pending_packets.retry_pending_packets()  # 重试未完成的 ARP 请求
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    router = Router(net)
    router.start()
