"""
SDN Controller tich hop:
  - Load Balancing (Least Connection Algorithm)
  - DDoS Detection (XGBoost ML model)
  - DDoS Prevention (Block port khi phat hien tan cong)

Ryu Controller + OpenFlow 1.3 + OVS + Mininet
Chay: ryu-manager integrated_controller.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, arp
from ryu.lib.packet import ether_types, in_proto, icmp, udp
from ryu.lib import hub

from datetime import datetime
import pandas as pd
import joblib
import json
import os
import time

# ══════════════════════════════════════════════════════════════
#  CAU HINH LOAD BALANCER
# ══════════════════════════════════════════════════════════════

VIRTUAL_IP  = '10.0.0.100'
VIRTUAL_MAC = '00:00:00:00:01:00'

SERVER_POOL = [
    {'ip': '10.0.0.1', 'mac': '00:00:00:00:00:01', 'name': 'h1'},
    {'ip': '10.0.0.2', 'mac': '00:00:00:00:00:02', 'name': 'h2'},
    {'ip': '10.0.0.3', 'mac': '00:00:00:00:00:03', 'name': 'h3'},
    {'ip': '10.0.0.4', 'mac': '00:00:00:00:00:04', 'name': 'h4'},
    {'ip': '10.0.0.5', 'mac': '00:00:00:00:00:05', 'name': 'h5'},
    {'ip': '10.0.0.6', 'mac': '00:00:00:00:00:06', 'name': 'h6'},
]

SERVER_IPS = [s['ip'] for s in SERVER_POOL]

# ══════════════════════════════════════════════════════════════
#  CAU HINH DDOS DETECTION
# ══════════════════════════════════════════════════════════════

MODEL_PATH       = '/home/minhviet/Documents/SDN/model/xgboost_ddos.pkl'
STATS_CSV        = 'PredictFlowStatsfile.csv'
MONITOR_INTERVAL = 10    # giay giua cac lan collect stats
BLOCK_TIMEOUT    = 120   # giay block port
DDOS_THRESHOLD   = 80    # % legitimate, duoi nguong nay = DDoS

CSV_HEADER = (
    'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,'
    'ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,'
    'idle_timeout,hard_timeout,flags,packet_count,byte_count,'
    'packet_count_per_second,packet_count_per_nsecond,'
    'byte_count_per_second,byte_count_per_nsecond\n'
)

LB_STATS_FILE = '/tmp/lb_stats.json'


class IntegratedController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IntegratedController, self).__init__(*args, **kwargs)

        # ── Load Balancer state ──
        self.conn_count  = {s['ip']: 0 for s in SERVER_POOL}
        self.session_map = {}
        self.total_req   = {s['ip']: 0 for s in SERVER_POOL}
        self.mac_to_port = {}
        self.request_log = []
        self.start_time  = time.time()

        # ── DDoS Prevention state ──
        self.mitigation     = 0
        self.arp_ip_to_port = {}
        self.blocked_ports  = {}

        # ── Network state ──
        self.datapaths = {}

        # ── Khoi dong ──
        self._init_csv()
        self.flow_model = None
        self._load_model()
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self._save_lb_stats()

        self.logger.info("=" * 60)
        self.logger.info("[CTRL] Integrated LB + DDoS Controller started")
        self.logger.info("[LB]   VIP = %s", VIRTUAL_IP)
        self.logger.info("[LB]   Servers = %s", [s['name'] for s in SERVER_POOL])
        self.logger.info("[DDOS] Block timeout = %ds", BLOCK_TIMEOUT)
        self.logger.info("=" * 60)

    # ══════════════════════════════════════════════════════════
    #  HELPERS CHUNG
    # ══════════════════════════════════════════════════════════

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

    def _learn_mac(self, dpid, mac, port):
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][mac] = port

    def _get_port(self, dpid, mac):
        return self.mac_to_port.get(dpid, {}).get(mac)

    # ══════════════════════════════════════════════════════════
    #  LOAD BALANCER — Least Connection
    # ══════════════════════════════════════════════════════════

    def _pick_server(self):
        """Chon server co active connection thap nhat."""
        return min(SERVER_POOL, key=lambda s: self.conn_count[s['ip']])

    def _save_lb_stats(self):
        stats = {
            'conn_count':       dict(self.conn_count),
            'total_req':        dict(self.total_req),
            'request_log':      self.request_log[-200:],
            'uptime':           round(time.time() - self.start_time, 1),
            'servers':          [s['name'] for s in SERVER_POOL],
            'server_ips':       SERVER_IPS,
            'ddos_mitigation':  self.mitigation,
        }
        try:
            with open(LB_STATS_FILE, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════
    #  DDOS DETECTION — Monitor + Predict
    # ══════════════════════════════════════════════════════════

    def _load_model(self):
        self.logger.info("[DDOS] Loading ML model...")
        try:
            self.flow_model = joblib.load(MODEL_PATH)
            self.logger.info("[DDOS] Model loaded OK")
        except Exception as e:
            self.logger.error("[DDOS] Model load FAILED: %s", e)

    def _init_csv(self):
        with open(STATS_CSV, 'w') as f:
            f.write(CSV_HEADER)

    def _monitor_loop(self):
        """Thread: moi MONITOR_INTERVAL giay collect + predict."""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL)
            self._flow_predict()

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.debug('register datapath: %016x', datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.debug('unregister datapath: %016x', datapath.id)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body      = ev.msg.body

        def has_ip_fields(flow):
            try:
                flow.match['ipv4_src']
                flow.match['ipv4_dst']
                flow.match['ip_proto']
                return True
            except KeyError:
                return False

        valid_flows = [f for f in body if f.priority == 1 and has_ip_fields(f)]

        with open(STATS_CSV, 'w') as f:
            f.write(CSV_HEADER)
            for stat in sorted(valid_flows, key=lambda x: (
                    x.match['ipv4_src'],
                    x.match['ipv4_dst'],
                    x.match['ip_proto'])):

                ip_src    = stat.match['ipv4_src']
                ip_dst    = stat.match['ipv4_dst']
                ip_proto  = stat.match['ip_proto']
                icmp_code = -1
                icmp_type_v = -1
                tp_src = tp_dst = 0

                if ip_proto == 1:
                    try:
                        icmp_code   = stat.match['icmpv4_code']
                        icmp_type_v = stat.match['icmpv4_type']
                    except KeyError:
                        pass
                elif ip_proto == 6:
                    try:
                        tp_src = stat.match['tcp_src']
                        tp_dst = stat.match['tcp_dst']
                    except KeyError:
                        pass
                elif ip_proto == 17:
                    try:
                        tp_src = stat.match['udp_src']
                        tp_dst = stat.match['udp_dst']
                    except KeyError:
                        pass

                flow_id = "{}{}{}{}{}".format(ip_src, tp_src, ip_dst, tp_dst, ip_proto)

                try:
                    pps  = stat.packet_count / stat.duration_sec
                    ppns = stat.packet_count / stat.duration_nsec
                except:
                    pps = ppns = 0
                try:
                    bps  = stat.byte_count / stat.duration_sec
                    bpns = stat.byte_count / stat.duration_nsec
                except:
                    bps = bpns = 0

                f.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, flow_id,
                            ip_src, tp_src, ip_dst, tp_dst, ip_proto,
                            icmp_code, icmp_type_v,
                            stat.duration_sec, stat.duration_nsec,
                            stat.idle_timeout, stat.hard_timeout,
                            stat.flags, stat.packet_count, stat.byte_count,
                            pps, ppns, bps, bpns))

    def _flow_predict(self):
        """Doc CSV, predict bang XGBoost, set mitigation."""
        try:
            df = pd.read_csv(STATS_CSV)

            if df.empty:
                self.logger.info("[DDOS] No flow data")
                return

            if self.flow_model is None:
                self.logger.warning("[DDOS] Model not loaded, skip predict")
                return

            df = df.drop(['timestamp', 'datapath_id', 'flow_id'], axis=1)
            df['ip_src'] = df['ip_src'].str.replace('.', '', regex=False).astype('int64')
            df['ip_dst'] = df['ip_dst'].str.replace('.', '', regex=False).astype('int64')

            y_pred = self.flow_model.predict(df.to_numpy())

            legit  = 0
            ddos   = 0
            victim = None

            for idx, label in enumerate(y_pred):
                if label == 0:
                    legit += 1
                else:
                    ddos += 1
                    victim = int(df.iloc[idx, 2]) % 20

            self.logger.info("------------------------------------------------------------------------------")
            self.logger.info("[DDOS] Legitimate: %d | DDoS: %d", legit, ddos)

            if (legit / len(y_pred) * 100) > DDOS_THRESHOLD:
                self.logger.info("[DDOS] Normal Traffic")
                self.mitigation = 0  # Reset khi traffic binh thuong
            else:
                if victim is not None:
                    self.logger.info(
                        "[DDOS] Attack detected! Victim: h%d (10.0.0.%d)",
                        victim, victim)
                self.mitigation = 1
                self._save_lb_stats()

            self.logger.info("------------------------------------------------------------------------------")

        except Exception as e:
            self.logger.error("[DDOS] flow_predict error: %s", e)
        finally:
            self._init_csv()

    # ══════════════════════════════════════════════════════════
    #  DDOS PREVENTION — Block port
    # ══════════════════════════════════════════════════════════

    def _block_port(self, datapath, portnumber):
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(in_port=portnumber)
        self.add_flow(datapath, 100, match, actions=[],
                      hard_timeout=BLOCK_TIMEOUT)
        dpid = datapath.id
        hub.spawn_after(BLOCK_TIMEOUT, self._unblock_port, dpid, portnumber)
        self.logger.info("[BLOCK] Port %d blocked for %ds", portnumber, BLOCK_TIMEOUT)

    def _unblock_port(self, dpid, portnumber):
        if dpid in self.blocked_ports and portnumber in self.blocked_ports[dpid]:
            self.blocked_ports[dpid].discard(portnumber)
            self.logger.info("[BLOCK] Port %d unblocked, ready to detect again", portnumber)

    # ══════════════════════════════════════════════════════════
    #  OPENFLOW EVENTS
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp
        self.logger.info("[SW] Connected: dpid=%s", dp.id)

        # Table-miss: gui len controller
        self.add_flow(dp, priority=0,
                      match=parser.OFPMatch(),
                      actions=[parser.OFPActionOutput(
                          ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

        # Drop LLDP
        self.add_flow(dp, priority=1,
                      match=parser.OFPMatch(eth_type=0x88cc),
                      actions=[])

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

        if eth.ethertype == 0x88cc:
            return
        if eth.dst in ('01:80:c2:00:00:00', '01:00:5e:00:00:fb'):
            return

        self._learn_mac(dpid, eth.src, in_port)
        self.datapaths[dpid] = dp

        # Init DDoS state cho dpid nay
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        self.blocked_ports.setdefault(dpid, set())

        # ── ARP ──
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if arp_pkt.opcode in (arp.ARP_REQUEST, arp.ARP_REPLY):
                if arp_pkt.src_ip not in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)
            self._handle_arp(dp, in_port, eth, arp_pkt, data)
            return

        # ── IP ──
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if not ip4:
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)], data)
            return

        srcip = ip4.src
        dstip = ip4.dst

        # ── Kiem tra DDoS truoc khi xu ly LB ──
        if self.mitigation:
            known_ips = self.arp_ip_to_port[dpid].get(in_port, [])
            if srcip not in known_ips:
                if in_port not in self.blocked_ports[dpid]:
                    self.logger.warning(
                        "[DDOS] Attack from port %d IP %s -> BLOCK", in_port, srcip)
                    self._block_port(dp, in_port)
                    self.blocked_ports[dpid].add(in_port)
                return

        # ── TCP den VIP: xu ly Load Balancer ──
        tcp4 = pkt.get_protocol(tcp.tcp)
        if tcp4 and dstip == VIRTUAL_IP:
            self._handle_lb(dp, in_port, eth, ip4, tcp4, data)
            return

        # ── Traffic thong thuong: forward binh thuong ──
        match = self._make_ip_match(parser, pkt, ip4)
        if match is None:
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)], data)
            return

        out_port = self._get_port(dpid, eth.dst)
        if out_port:
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, priority=1, match=match,
                          actions=actions, idle_timeout=20, hard_timeout=100)
            self.send_pkt_out(dp, in_port, actions, data)
        else:
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)], data)

    def _make_ip_match(self, parser, pkt, ip4):
        """Tao OFPMatch theo protocol."""
        srcip = ip4.src
        dstip = ip4.dst
        proto = ip4.proto

        if proto == in_proto.IPPROTO_ICMP:
            t = pkt.get_protocol(icmp.icmp)
            if t:
                return parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=srcip, ipv4_dst=dstip, ip_proto=proto,
                    icmpv4_code=t.code, icmpv4_type=t.type)
        elif proto == in_proto.IPPROTO_TCP:
            t = pkt.get_protocol(tcp.tcp)
            if t:
                return parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=srcip, ipv4_dst=dstip, ip_proto=proto,
                    tcp_src=t.src_port, tcp_dst=t.dst_port)
        elif proto == in_proto.IPPROTO_UDP:
            u = pkt.get_protocol(udp.udp)
            if u:
                return parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=srcip, ipv4_dst=dstip, ip_proto=proto,
                    udp_src=u.src_port, udp_dst=u.dst_port)
        return None

    # ══════════════════════════════════════════════════════════
    #  LOAD BALANCER HANDLER
    # ══════════════════════════════════════════════════════════

    def _handle_lb(self, dp, in_port, eth_pkt, ip4, tcp4, data):
        parser    = dp.ofproto_parser
        ofp       = dp.ofproto
        dpid      = dp.id
        src_ip    = ip4.src
        src_port  = tcp4.src_port
        tcp_flags = tcp4.bits
        FIN = 0x01
        RST = 0x04

        session_key = (src_ip, src_port)

        # FIN/RST: dong session
        if tcp_flags & (FIN | RST):
            if session_key in self.session_map:
                server = self.session_map.pop(session_key)
                self.conn_count[server['ip']] = max(
                    0, self.conn_count[server['ip']] - 1)
                self.logger.info("[LB] CLOSE %s:%d | %s conn=%d",
                    src_ip, src_port,
                    server['name'], self.conn_count[server['ip']])
                self._save_lb_stats()
            return

        # SYN: session moi -> chon server Least Connection
        if session_key not in self.session_map:
            server = self._pick_server()
            self.session_map[session_key] = server
            self.conn_count[server['ip']] += 1
            self.total_req[server['ip']]  += 1
            self.request_log.append({
                'time':          round(time.time() - self.start_time, 2),
                'server':        server['name'],
                'server_ip':     server['ip'],
                'client':        src_ip,
                'conn_snapshot': dict(self.conn_count),
            })
            self.logger.info("[LB] NEW %s:%d -> %s (%s) | counts=%s",
                src_ip, src_port,
                server['name'], server['ip'],
                self.conn_count)
            self._save_lb_stats()
        else:
            server = self.session_map[session_key]

        srv_ip   = server['ip']
        srv_mac  = server['mac']
        out_port = self._get_port(dpid, srv_mac)

        if out_port is None:
            self.logger.warning("[LB] No port for %s, flooding", srv_mac)
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)], data)
            return

        # Flow client -> server (DNAT)
        match_c2s = parser.OFPMatch(
            in_port=in_port, eth_type=0x0800, ip_proto=6,
            ipv4_src=src_ip, ipv4_dst=VIRTUAL_IP, tcp_src=src_port)
        actions_c2s = [
            parser.OFPActionSetField(eth_dst=srv_mac),
            parser.OFPActionSetField(ipv4_dst=srv_ip),
            parser.OFPActionOutput(out_port),
        ]
        self.add_flow(dp, priority=10, match=match_c2s,
                      actions=actions_c2s, idle_timeout=30)

        # Flow server -> client (SNAT)
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

        self.logger.info("[LB] Flow installed: %s:%d -> %s port=%d",
            src_ip, src_port, srv_ip, out_port)
        self.send_pkt_out(dp, in_port, actions_c2s, data)

    # ══════════════════════════════════════════════════════════
    #  ARP HANDLER
    # ══════════════════════════════════════════════════════════

    def _handle_arp(self, dp, in_port, eth_pkt, arp_pkt, data):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        self._learn_mac(dp.id, arp_pkt.src_mac, in_port)
        self.logger.info("[ARP] dpid=%s port=%d %s->%s op=%s",
            dp.id, in_port, arp_pkt.src_ip, arp_pkt.dst_ip,
            'REQ' if arp_pkt.opcode == 1 else 'REP')

        # Chi tra loi ARP request den VIP
        if arp_pkt.opcode != arp.ARP_REQUEST or arp_pkt.dst_ip != VIRTUAL_IP:
            out_port = self._get_port(dp.id, eth_pkt.dst)
            if out_port:
                self.add_flow(dp, priority=5,
                              match=parser.OFPMatch(eth_type=0x0806,
                                                    eth_dst=eth_pkt.dst),
                              actions=[parser.OFPActionOutput(out_port)],
                              idle_timeout=60)
            self.send_pkt_out(dp, in_port,
                              [parser.OFPActionOutput(ofp.OFPP_FLOOD)], data)
            return

        # Tra loi ARP: VIP -> VIRTUAL_MAC
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
        self.logger.info("[ARP] Reply %s=%s -> %s",
            VIRTUAL_IP, VIRTUAL_MAC, arp_pkt.src_ip)