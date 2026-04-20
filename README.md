How to Run
1. Start the SDN Controller
```bash
ryu-manager controller.py
```
2. Run the Network Topology (Mininet)
```bash
sudo python topology.py
```
3. Attack
```bash
# ICMP flood
hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1

# UDP flood
hping3 -2 -V -d 120 -w 64 --rand-source --flood 10.0.0.1 

# SYN flood
hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1

# TCP flood
hping3 -A -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1
```
