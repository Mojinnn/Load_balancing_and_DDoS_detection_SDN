Load balancing and DDoS detection SDN
## How to run project:
### Step 1: Run topology:
Open Terminal 1:
```bash
sudo python3 topology/topo.py
```
### Step 2: Run controller algorithm:
Open Terminal 2:
```bash
~/ryu-venv-py39/bin/ryu-manager --verbose controller/lb_least_conn.py
```
### Step 3: Run server:
Back to Terminal 1:
```bash
mininet> h1 python3 benchmark/server.py 10.0.0.1 h1 &
mininet> h2 python3 benchmark/server.py 10.0.0.2 h2 &
mininet> h3 python3 benchmark/server.py 10.0.0.3 h3 &
mininet> h4 python3 benchmark/server.py 10.0.0.4 h4 &
mininet> h5 python3 benchmark/server.py 10.0.0.5 h5 &
mininet> h6 python3 benchmark/server.py 10.0.0.6 h6 &
```
### Step 4: Run benchmark:
``` bash
mininet> c1 python3 benchmark/run_benchmark.py 30
```
### Step 5: Permission to run folder:
``` bash
sudo chown -R mojinn:mojinn ~/SDN_project/Load_Balancing_Least_Conn/visualize/results/
```
### Step 6: Visualize:
``` bash
python3 visualize/plot_results.py <folder_name>
```


