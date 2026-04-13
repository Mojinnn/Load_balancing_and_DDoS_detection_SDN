Load balancing and DDoS detection SDN
## How to run project:
- Terminal 1: sudo python3 topology/topo.py
- Terminal 2: (venv) ~/ryu-venv-py39/bin/ryu-manager --verbose controller/lb_least_conn.py
- Ternminal 1: run server
" mininet> h1 python3 benchmark/server.py 10.0.0.1 h1 &
mininet> h2 python3 benchmark/server.py 10.0.0.2 h2 &
mininet> h3 python3 benchmark/server.py 10.0.0.3 h3 &
mininet> h4 python3 benchmark/server.py 10.0.0.4 h4 &
mininet> h5 python3 benchmark/server.py 10.0.0.5 h5 &
mininet> h6 python3 benchmark/server.py 10.0.0.6 h6 &
"  
