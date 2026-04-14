"""
SDN Load Balancer — Least Connection Algorithm
Ryu Controller + OpenFlow 1.3 + OVS + Mininet
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, arp
import time
import json
import os

# ── Virtual IP (VIP) ──
VIRTUAL_IP  = '10.0.0.100'
VIRTUAL_MAC = '00:00:00:00:01:00'

# ── Server pool ──
SERVER_POOL = [
    {'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01', 'name': 'h1'},
    {'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'name': 'h2'},
    {'ip': '10.0.0.3', 'mac': '00:00:00:00:00:03', 'name': 'h3'},
    {'ip': '10.0.0.4', 'mac': '00:00:00:00:00:04', 'name': 'h4'},
    {'ip': '10.0.0.5', 'mac': '00:00:00:00:00:05', 'name': 'h5'},
    {'ip': '10.0.0.6', 'mac': '00:00:00:00:00:06', 'name': 'h6'},
]

RESULTS_FILE = '/tmp/lb_stats.json'


class LeastConnLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ── Least Connection state ──
        self.conn_count  = {s['ip']: 0 for s in SERVER_POOL}
        self.session_map = {}   # (src_ip, src_port) → server
        self.total_req   = {s['ip']: 0 for s in SERVER_POOL}

        # ── Network state ──
        self.mac_to_port = {}   # {dpid: {mac: port}}
        self.datapaths   = {}   # {dpid: dp}

        # ── Metrics ──
        self.request_log = []   # [{time, server, latency}]
        self.start_time  = time.time()

        self._save_stats()
        self.logger.info("=" * 50)
        self.logger.info("[LC-LB] Least Connection LB started")
        self.logger.info(f"[LC-LB] VIP = {VIRTUAL_IP}")
        self.logger.info(f"[LC-LB] Servers = {[s['name'] for s in SERVER_POOL]}")
        self.logger.info("=" * 50)

    # ─────────────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────────────

    def add_flow(self, dp, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        inst   = [parser.OFPInstructionActions(
                      ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority,
            match=match, instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout)
        dp.send_msg(mod)

    def send_pkt_out(self, dp, in_port, actions, data):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data)
        dp.send_msg(out)

    def _learn(self, dpid, mac, port):
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][mac] = port

    def _get_port(self, dpid, mac):
        return self.mac_to_port.get(dpid, {}).get(mac)

    def _pick_server(self):
        return min(SERVER_POOL,
                   key=lambda s: self.conn_count[s['ip']])

    def _save_stats(self):
        stats = {
            'conn_count':  dict(self.conn_count),
            'total_req':   dict(self.total_req),
            'request_log': self.request_log[-200:],
            'uptime':      round(time.time() - self.start_time, 1),
            'servers':     [s['name'] for s in SERVER_POOL],
            'server_ips':  [s['ip']   for s in SERVER_POOL],
        }
        try:
            with open(RESULTS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────
    #  OpenFlow Events
    # ─────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self.logger.info(f"[SW] Connected: dpid={dp.id}")

        # Table-miss
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
                       ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match, actions=actions)

        lldp_match = parser.OFPMatch(eth_type=0x88cc)
        self.add_flow(dp, priority=1, match=lldp_match, actions=[])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser
        in_port = msg.match['in_port']
        dpid    = dp.id
        data    = msg.data

        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # Bypass LLDP, STP, mDNS
        if eth.ethertype == 0x88cc:
            return
        if eth.dst in ('01:80:c2:00:00:00', '01:00:5e:00:00:fb'):
            return

        self._learn(dpid, eth.src, in_port)
        self.datapaths[dpid] = dp

        # ── ARP ────────────────────────────────────────
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(dp, in_port, eth, arp_pkt, data)
            return

        # ── TCP/IP ─────────────────────────────────────
        ip4  = pkt.get_protocol(ipv4.ipv4)
        tcp4 = pkt.get_protocol(tcp.tcp)

        if not ip4 or not tcp4:
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                              data)
            return

        src_ip    = ip4.src
        dst_ip    = ip4.dst
        src_port  = tcp4.src_port
        tcp_flags = tcp4.bits

        # Traffic can not reach VIP → forward normally
        if dst_ip != VIRTUAL_IP:
            dst_mac  = eth.dst
            out_port = self._get_port(dpid, dst_mac)
            action   = [parser.OFPActionOutput(
                            out_port if out_port else ofp.OFPP_FLOOD)]
            self.send_pkt_out(dp, in_port, action, data)
            return

        session_key = (src_ip, src_port)
        FIN = 0x01; RST = 0x04

        # ── FIN/RST: end session ──
        if tcp_flags & (FIN | RST):
            if session_key in self.session_map:
                server = self.session_map.pop(session_key)
                self.conn_count[server['ip']] = max(
                    0, self.conn_count[server['ip']] - 1)
                self.logger.info(
                    f"[LC] CLOSE {src_ip}:{src_port} | "
                    f"{server['name']} conn={self.conn_count[server['ip']]}")
                self._save_stats()
            return

        # ── SYN: new session → pick server Least Connection ──
        t0 = time.time()
        if session_key not in self.session_map:
            server = self._pick_server()
            self.session_map[session_key] = server
            self.conn_count[server['ip']] += 1
            self.total_req[server['ip']]  += 1
            latency_ms = round((time.time() - t0) * 1000, 3)
            self.request_log.append({
                'time':      round(time.time() - self.start_time, 2),
                'server':    server['name'],
                'server_ip': server['ip'],
                'client':    src_ip,
                'latency':   latency_ms,
                'conn_snapshot': dict(self.conn_count),
            })
            self.logger.info(
                f"[LC] NEW {src_ip}:{src_port} → {server['name']} "
                f"({server['ip']}) | counts={self.conn_count}")
            self._save_stats()
        else:
            server = self.session_map[session_key]

        srv_ip  = server['ip']
        srv_mac = server['mac']

        # Find port reach server
        out_port = self._get_port(dpid, srv_mac)
        if out_port is None:
            self.logger.warning(
                f"[LC] No port for {srv_mac} on dpid={dpid}, flooding")
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                              data)
            return

        # ── Install flow client to server (DNAT) ──
        match_c2s = parser.OFPMatch(
            in_port=in_port, eth_type=0x0800, ip_proto=6,
            ipv4_src=src_ip, ipv4_dst=VIRTUAL_IP,
            tcp_src=src_port)
        actions_c2s = [
            parser.OFPActionSetField(eth_dst=srv_mac),
            parser.OFPActionSetField(ipv4_dst=srv_ip),
            parser.OFPActionOutput(out_port),
        ]
        self.add_flow(dp, priority=10, match=match_c2s,
                      actions=actions_c2s, idle_timeout=30)

        # ── Install flow server to client (SNAT) ──
        match_s2c = parser.OFPMatch(
            eth_type=0x0800, ip_proto=6,
            ipv4_src=srv_ip, ipv4_dst=src_ip, tcp_dst=src_port)
        actions_s2c = [
            parser.OFPActionSetField(eth_src=VIRTUAL_MAC),
            parser.OFPActionSetField(ipv4_src=VIRTUAL_IP),
            parser.OFPActionOutput(in_port),
        ]
        self.add_flow(dp, priority=10, match=match_s2c,
                      actions=actions_s2c, idle_timeout=30)

        self.logger.info(
            f"[LC] Flow installed dpid={dpid}: "
            f"{src_ip}:{src_port} → {srv_ip} port={out_port}")

        self.send_pkt_out(dp, in_port, actions_c2s, data)

    # ─────────────────────────────────────────────────────
    #  ARP Handler
    # ─────────────────────────────────────────────────────

    def _handle_arp(self, dp, in_port, eth_pkt, arp_pkt, data):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        self._learn(dp.id, arp_pkt.src_mac, in_port)
        self.logger.info(
            f"[ARP] dpid={dp.id} port={in_port} "
            f"{arp_pkt.src_ip}→{arp_pkt.dst_ip} "
            f"op={'REQ' if arp_pkt.opcode == 1 else 'REP'}")

        if (arp_pkt.opcode != arp.ARP_REQUEST
                or arp_pkt.dst_ip != VIRTUAL_IP):
            
            out_port = self._get_port(dp.id, eth_pkt.dst)
            if out_port:
                match = parser.OFPMatch(
                    eth_type=0x0806,
                    eth_dst=eth_pkt.dst)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(dp, priority=5, match=match,
                          actions=actions, idle_timeout=60)
            self.send_pkt_out(dp, in_port,
                          [parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                          data)
            return

        # Reply ARP: VIP to VIRTUAL_MAC
        e = ethernet.ethernet(
            dst=eth_pkt.src, src=VIRTUAL_MAC, ethertype=0x0806)
        a = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=VIRTUAL_MAC, src_ip=VIRTUAL_IP,
            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=p.data)
        dp.send_msg(out)
        self.logger.info(
            f"[ARP] Reply {VIRTUAL_IP}={VIRTUAL_MAC} → {arp_pkt.src_ip}")

    # ─────────────────────────────────────────────────────
    #  Hook cho DDoS ML module (bạn của bạn implement)
    # ─────────────────────────────────────────────────────

    def _ddos_hook(self, src_ip: str) -> bool:
        """
        Trả về True nếu src_ip bị classify là DDoS.
        Tích hợp: override hàm này hoặc gọi REST API.
        """
        return False

    def _install_drop(self, dp, src_ip: str):
        parser = dp.ofproto_parser
        match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self.add_flow(dp, priority=100, match=match,
                      actions=[], hard_timeout=60)
        self.logger.warning(f"[DDOS] DROP {src_ip}")
