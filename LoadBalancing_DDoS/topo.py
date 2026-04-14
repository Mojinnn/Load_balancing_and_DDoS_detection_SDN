"""
Mininet Topology — SDN Load Balancer (Least Connection)
4 OVS switch, 6 server hosts, 2 client hosts
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
import os, time, sys


class LBTopo(Topo):
    """
    Topology:
        c1, c2 ──→ s1 (LB switch) ──→ s2 ──→ h1, h2
                                   ──→ s3 ──→ h3, h4
                                   ──→ s4 ──→ h5, h6
    """
    def build(self):
        # Core LB switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        # Edge switches
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')

        # Server hosts — IP/MAC tĩnh để controller nhận diện
        servers = [
            ('h1', '10.0.0.1', '00:00:00:00:00:01', s2),
            ('h2', '10.0.0.2', '00:00:00:00:00:02', s2),
            ('h3', '10.0.0.3', '00:00:00:00:00:03', s3),
            ('h4', '10.0.0.4', '00:00:00:00:00:04', s3),
            ('h5', '10.0.0.5', '00:00:00:00:00:05', s4),
            ('h6', '10.0.0.6', '00:00:00:00:00:06', s4),
        ]
        for name, ip, mac, sw in servers:
            h = self.addHost(name, ip=f'{ip}/24', mac=mac)
            self.addLink(h, sw, cls=TCLink, bw=100)

        # Client hosts — cùng subnet với VIP (10.0.0.x)
        c1 = self.addHost('c1', ip='10.0.0.50/24',
                          mac='00:00:00:00:00:fe')
        c2 = self.addHost('c2', ip='10.0.0.51/24',
                          mac='00:00:00:00:00:ff')
        self.addLink(c1, s1, cls=TCLink, bw=100)
        self.addLink(c2, s1, cls=TCLink, bw=100)

        # Switch links — không cần rate limit
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)


def setup_ovs():
    """Tắt STP, set OpenFlow13, xóa flow cũ."""
    switches = ['s1', 's2', 's3', 's4']
    for sw in switches:
        os.system(f'ovs-vsctl set bridge {sw} stp_enable=false '
                  f'protocols=OpenFlow13 2>/dev/null')
        os.system(f'ovs-ofctl del-flows {sw} -O OpenFlow13 2>/dev/null')
    print(f'[TOPO] OVS configured: STP=off, OF1.3, flows cleared')


def print_port_map():
    """In ra port mapping để debug."""
    print("\n=== Port mapping ===")
    for sw in ['s1', 's2', 's3', 's4']:
        ret = os.popen(
            f'ovs-ofctl show {sw} -O OpenFlow13 2>/dev/null'
            f' | grep "eth" | head -6').read()
        print(f"[{sw}]")
        for line in ret.strip().splitlines():
            print(f"  {line.strip()}")
    print()


def verify_flows():
    """Kiểm tra table-miss flow đã được cài chưa."""
    print("\n=== Flow table s1 ===")
    os.system('ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null')
    print()


if __name__ == '__main__':
    # os.system('mn -c 2>/dev/null')
    # time.sleep(1)

    topo = LBTopo()
    net = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=RemoteController,
        autoSetMacs=False,
    )

    print('[TOPO] Starting network...')
    net.start()

    # KHÔNG gọi del-flows sau khi switch đã connect
    # Chỉ tắt STP và set protocol — KHÔNG xóa flow
    for sw in ['s1', 's2', 's3', 's4']:
        os.system(f'ovs-vsctl set bridge {sw} stp_enable=false '
                  f'protocols=OpenFlow13 2>/dev/null')
    print('[TOPO] OVS: STP=off, OF1.3 set (flows preserved)')

    time.sleep(2)  # Đợi controller cài flow

    print_port_map()
    verify_flows()   # Bây giờ sẽ thấy flow

    print('='*50)
    print('[TOPO] Ready!')
    CLI(net)
    net.stop()
