# from ryu.controller import ofp_event
# from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
# from ryu.controller.handler import set_ev_cls
# from ryu.lib import hub
# from datetime import datetime
# import pandas as pd
# import joblib
# from sklearn.neural_network import MLPClassifier
# from sklearn.metrics import accuracy_score

# # import detection_module
# import prevention_module
# #import mitigation_module

# # class SimpleMonitor13(detection_module.SimpleSwitch13):
# class SimpleMonitor13(prevention_module.SimpleSwitch13):
# #class SimpleMonitor13(mitigation_module.SimpleSwitch13):

#     def __init__(self, *args, **kwargs):

#         super(SimpleMonitor13, self).__init__(*args, **kwargs)
#         self.datapaths = {}

#         self.monitor_thread = hub.spawn(self._monitor)

#         self.flow_loading()

#     @set_ev_cls(ofp_event.EventOFPStateChange,
#                 [MAIN_DISPATCHER, DEAD_DISPATCHER])
#     def _state_change_handler(self, ev):
#         datapath = ev.datapath
#         if ev.state == MAIN_DISPATCHER:
#             if datapath.id not in self.datapaths:
#                 self.logger.debug('register datapath: %016x', datapath.id)
#                 self.datapaths[datapath.id] = datapath
#         elif ev.state == DEAD_DISPATCHER:
#             if datapath.id in self.datapaths:
#                 self.logger.debug('unregister datapath: %016x', datapath.id)
#                 del self.datapaths[datapath.id]

#     def _monitor(self):
#         while True:
#             for dp in self.datapaths.values():
#                 self._request_stats(dp)
#             hub.sleep(10)

#             self.flow_predict()

#     def _request_stats(self, datapath):
#         self.logger.debug('send stats request: %016x', datapath.id)
#         parser = datapath.ofproto_parser

#         req = parser.OFPFlowStatsRequest(datapath)
#         datapath.send_msg(req)

#     @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
#     def _flow_stats_reply_handler(self, ev):

#         timestamp = datetime.now()
#         timestamp = timestamp.timestamp()

#         file0 = open("PredictFlowStatsfile.csv","w")
#         file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
#         body = ev.msg.body
#         icmp_code = -1
#         icmp_type = -1
#         tp_src = 0
#         tp_dst = 0

#         def has_ip_fields(flow):
#             try:
#                 _ = flow.match['ipv4_src']
#                 _ = flow.match['ipv4_dst']
#                 _ = flow.match['ip_proto']
#                 return True
#             except KeyError:
#                 return False

#         valid_flows = [flow for flow in body if flow.priority == 1 and has_ip_fields(flow)]

#         for stat in sorted(valid_flows, key=lambda flow:
#             (flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

#             ip_src = stat.match['ipv4_src']
#             ip_dst = stat.match['ipv4_dst']
#             ip_proto = stat.match['ip_proto']

#             if stat.match['ip_proto'] == 1:
#                 try:
#                     icmp_code = stat.match['icmpv4_code']
#                     icmp_type = stat.match['icmpv4_type']
#                 except KeyError:
#                     icmp_code = -1
#                     icmp_type = -1

#             elif stat.match['ip_proto'] == 6:
#                 try:
#                     tp_src = stat.match['tcp_src']
#                     tp_dst = stat.match['tcp_dst']
#                 except KeyError:
#                     tp_src = 0
#                     tp_dst = 0

#             elif stat.match['ip_proto'] == 17:
#                 try:
#                     tp_src = stat.match['udp_src']
#                     tp_dst = stat.match['udp_dst']
#                 except KeyError:
#                     tp_src = 0
#                     tp_dst = 0

#             flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

#             try:
#                 packet_count_per_second = stat.packet_count / stat.duration_sec
#                 packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
#             except:
#                 packet_count_per_second = 0
#                 packet_count_per_nsecond = 0

#             try:
#                 byte_count_per_second = stat.byte_count / stat.duration_sec
#                 byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
#             except:
#                 byte_count_per_second = 0
#                 byte_count_per_nsecond = 0

#             file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
#                 .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
#                         stat.match['ip_proto'], icmp_code, icmp_type,
#                         stat.duration_sec, stat.duration_nsec,
#                         stat.idle_timeout, stat.hard_timeout,
#                         stat.flags, stat.packet_count, stat.byte_count,
#                         packet_count_per_second, packet_count_per_nsecond,
#                         byte_count_per_second, byte_count_per_nsecond))

#         file0.close()

#     def flow_loading(self):
#         self.logger.info("Model Loading...")

#         self.flow_model = joblib.load('/home/minhviet/Documents/SDN/model/xgboost_ddos.pkl')

#         self.logger.info("------------------------------------------------------------------------------")

#     def flow_predict(self):
#         try:
#             predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
            
#             predict_flow_dataset = predict_flow_dataset.drop(['timestamp', 'datapath_id','flow_id'], axis=1)
            
#             predict_flow_dataset['ip_src'] = predict_flow_dataset['ip_src'].str.replace('.', '').astype('int64')
#             predict_flow_dataset['ip_dst'] = predict_flow_dataset['ip_dst'].str.replace('.', '').astype('int64')

#             X_predict_flow = predict_flow_dataset.to_numpy()
            
#             y_flow_pred = self.flow_model.predict(X_predict_flow)
            
#             legitimate_trafic = 0
#             ddos_trafic = 0
            
#             for i in y_flow_pred:
#                 if i == 0:
#                     legitimate_trafic = legitimate_trafic + 1
#                 else:
#                     ddos_trafic = ddos_trafic + 1
#                     victim = int(predict_flow_dataset.iloc[i, 2])%20
                    
#             self.logger.info("------------------------------------------------------------------------------")
#             if (legitimate_trafic/len(y_flow_pred)*100) > 80:
#                 self.logger.info("Normal Traffic")
#             else:
#                 self.logger.info("Attack DDOS at host h{} have ip address 10.0.0.{}".format(victim, victim))
#                 self.mitigation = 1
#             self.logger.info("------------------------------------------------------------------------------")
            
#             file0 = open("PredictFlowStatsfile.csv","w")
            
#             file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
#             file0.close()

#         except:
#             pass

        
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime
import pandas as pd
import joblib
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score

import prevention_module

class SimpleMonitor13(prevention_module.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}

        self.monitor_thread = hub.spawn(self._monitor)

        self.flow_loading()

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()

        file0 = open("PredictFlowStatsfile.csv","w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        def has_ip_fields(flow):
            try:
                _ = flow.match['ipv4_src']
                _ = flow.match['ipv4_dst']
                _ = flow.match['ip_proto']
                return True
            except KeyError:
                return False

        valid_flows = [flow for flow in body if flow.priority == 1 and has_ip_fields(flow)]

        for stat in sorted(valid_flows, key=lambda flow:
            (flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            if stat.match['ip_proto'] == 1:
                try:
                    icmp_code = stat.match['icmpv4_code']
                    icmp_type = stat.match['icmpv4_type']
                except KeyError:
                    icmp_code = -1
                    icmp_type = -1

            elif stat.match['ip_proto'] == 6:
                try:
                    tp_src = stat.match['tcp_src']
                    tp_dst = stat.match['tcp_dst']
                except KeyError:
                    tp_src = 0
                    tp_dst = 0

            elif stat.match['ip_proto'] == 17:
                try:
                    tp_src = stat.match['udp_src']
                    tp_dst = stat.match['udp_dst']
                except KeyError:
                    tp_src = 0
                    tp_dst = 0

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0

            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                        stat.match['ip_proto'], icmp_code, icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count, stat.byte_count,
                        packet_count_per_second, packet_count_per_nsecond,
                        byte_count_per_second, byte_count_per_nsecond))

        file0.close()

    def flow_loading(self):
        self.logger.info("Model Loading...")
        self.flow_model = joblib.load('/home/minhviet/Documents/SDN/model/xgboost_ddos.pkl')
        self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            # Kiểm tra dataset rỗng
            if predict_flow_dataset.empty:

                self.logger.info("No flow data")
                return

            predict_flow_dataset = predict_flow_dataset.drop(
                ['timestamp', 'datapath_id', 'flow_id'], axis=1
            )

            predict_flow_dataset['ip_src'] = (
                predict_flow_dataset['ip_src'].str.replace('.', '', regex=False).astype('int64')
            )
            predict_flow_dataset['ip_dst'] = (
                predict_flow_dataset['ip_dst'].str.replace('.', '', regex=False).astype('int64')
            )

            X_predict_flow = predict_flow_dataset.to_numpy()
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0
            victim = None

            # Fix bug index: dùng enumerate thay vì dùng label làm index
            for idx, label in enumerate(y_flow_pred):
                if label == 0:
                    legitimate_trafic += 1
                else:
                    ddos_trafic += 1
                    victim = int(predict_flow_dataset.iloc[idx, 2]) % 20

            self.logger.info("------------------------------------------------------------------------------")
            self.logger.info("Legitimate: {} | DDoS: {}".format(legitimate_trafic, ddos_trafic))

            if (legitimate_trafic / len(y_flow_pred) * 100) > 80:
                self.logger.info("Normal Traffic")
                self.mitigation = 0  # Reset mitigation khi traffic bình thường

            else:
                if victim is not None:
                    self.logger.info(
                        "Attack DDOS at host h{} have ip address 10.0.0.{}".format(victim, victim)
                    )
                self.mitigation = 1

            self.logger.info("------------------------------------------------------------------------------")

        except Exception as e:
            self.logger.error("flow_predict error: {}".format(e))  # Log lỗi thay vì im lặng

        finally:
            #  Dùng finally đảm bảo luôn reset file
            with open("PredictFlowStatsfile.csv", "w") as f:
                f.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,'
                        'tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,'
                        'flow_duration_nsec,idle_timeout,hard_timeout,flags,'
                        'packet_count,byte_count,packet_count_per_second,'
                        'packet_count_per_nsecond,byte_count_per_second,'
                        'byte_count_per_nsecond\n')