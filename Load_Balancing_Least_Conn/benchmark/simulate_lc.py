# benchmark/simulate_lc.py
"""
Mô phỏng để làm rõ Least Connection vs Round Robin
- h1, h2: SLOW server (delay 3s) → conn count tăng dần
- h3-h6:  FAST server (delay 0s) → LC ưu tiên chúng
- Nhiều client gửi đồng thời → conn overlap → LC phân biệt được
"""
import threading, subprocess, time, json
from collections import defaultdict

VIP          = '10.0.0.100'
SERVER_IPS   = ['10.0.0.1','10.0.0.2','10.0.0.3',
                '10.0.0.4','10.0.0.5','10.0.0.6']
SERVER_NAMES = ['h1','h2','h3','h4','h5','h6']

results  = defaultdict(int)
latency  = []
lock     = threading.Lock()


def send_request(client_id, req_id):
    for attempt in range(3):   # thử lại tối đa 3 lần
        t0 = time.time()
        try:
            out = subprocess.check_output(
                ['wget', '-qO-', f'http://{VIP}/',
                 '--timeout=15', '--tries=1'],
                stderr=subprocess.DEVNULL, timeout=16)
            lat = (time.time() - t0) * 1000
            body = out.decode('utf-8', errors='ignore')
            server = 'unknown'
            for ip in SERVER_IPS:
                if ip in body:
                    server = ip
                    break
            with lock:
                results[server] += 1
                latency.append(lat)
            print(f'  [c{client_id}] req#{req_id} → {server} ({lat:.0f}ms)')
            return
        except Exception:
            time.sleep(0.3)   # đợi rồi thử lại
    with lock:
        results['error'] += 1
    print(f'  [c{client_id}] req#{req_id} → ERROR (3 attempts)')


def run_concurrent_wave(n_clients, n_requests_each):
    """
    Mỗi client gửi n_requests_each request ĐỒNG THỜI
    → Overlap connection → conn_count tăng thực sự
    """
    print(f'\n[SIM] {n_clients} clients {n_requests_each} requests')
    print(f'      = {n_clients * n_requests_each} requests tổng')
    print(f'      Concurrent overlap → LC sẽ tránh slow server\n')

    threads = []
    for c in range(n_clients):
        for r in range(n_requests_each):
            t = threading.Thread(target=send_request, args=(c+1, r+1))
            threads.append(t)

    # Start tất cả gần như cùng lúc
    for t in threads:
        t.start()
        time.sleep(0.15)  # 50ms gap

    for t in threads:
        t.join(timeout=20)


if __name__ == '__main__':
    print('='*55)
    print('  LC Simulation — Heterogeneous Server Speed')
    print('='*55)
    print('  h1, h2: SLOW (3s delay) → sẽ tích lũy conn')
    print('  h3-h6:  FAST (0s delay) → LC ưu tiên')
    print()
    print('  Đảm bảo đã chạy:')
    print('  h1 python3 benchmark/server_slow.py 10.0.0.1 h1 3 &')
    print('  h2 python3 benchmark/server_slow.py 10.0.0.2 h2 3 &')
    print('  h3 python3 benchmark/server.py 10.0.0.3 h3 &')
    print('  ...h4,h5,h6 tương tự...')
    input('\n  Nhấn Enter để bắt đầu...')

    t_start = time.time()
    run_concurrent_wave(n_clients=4, n_requests_each=5)
    elapsed = time.time() - t_start

    # ── Kết quả ──
    print('\n' + '='*55)
    print('  SIMULATION RESULTS')
    print('='*55)
    total = sum(v for k,v in results.items() if k != 'error')
    print(f'\n  {"Server":<12} {"Count":>6} {"% share":>8} {"Expected (LC)":>15}')
    print(f'  {"-"*45}')
    for ip, name in zip(SERVER_IPS, SERVER_NAMES):
        count = results.get(ip, 0)
        pct   = count/total*100 if total > 0 else 0
        # LC nên ưu tiên fast server (h3-h6)
        expect = 'LOW (slow)' if name in ['h1','h2'] else 'HIGH (fast)'
        print(f'  {name} ({ip})  {count:>4}   {pct:>6.1f}%   {expect:>15}')

    valid_lat = [l for l in latency if l < 15000]
    if valid_lat:
        print(f'\n  Avg latency: {sum(valid_lat)/len(valid_lat):.1f}ms')
        print(f'  Max latency: {max(valid_lat):.1f}ms')

    # Đánh giá LC có hoạt động đúng không
    slow_count = results.get('10.0.0.1',0) + results.get('10.0.0.2',0)
    fast_count = sum(results.get(ip,0) for ip in SERVER_IPS[2:])
    print(f'\n  Slow servers (h1+h2): {slow_count} requests')
    print(f'  Fast servers (h3-h6): {fast_count} requests')
    if fast_count > slow_count * 2:
        print('  ✓ Least Connection hoạt động đúng — ưu tiên fast server!')
    else:
        print('  ✗ Kết quả chưa rõ — thử tăng delay hoặc n_clients')

    print(f'\n  Tổng thời gian: {elapsed:.1f}s')
    print('='*55)

    # Lưu kết quả
    with open('/tmp/lc_simulation.json', 'w') as f:
        json.dump({
            'distribution': dict(results),
            'latency': latency,
            'slow_servers': ['h1','h2'],
            'fast_servers': ['h3','h4','h5','h6'],
        }, f, indent=2)
    print('  Saved: /tmp/lc_simulation.json')
