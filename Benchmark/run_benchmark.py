#!/usr/bin/env python3
"""
Benchmark — So sánh CÓ LB vs KHÔNG LB
Chạy trong Mininet: mininet> c1 python3 benchmark/run_benchmark.py [n_requests]

Cách đo đúng:
- CÓ LB:    gửi đến VIP 10.0.0.100 (Ryu phân phối Least Connection)
- KHÔNG LB: gửi thẳng đến h1 10.0.0.1 (Ryu vẫn chạy, chỉ không qua VIP)
- Không bao giờ tắt Ryu trong lúc test

Kết quả lưu vào: visualize/results/<timestamp>/
"""

import subprocess, threading, time, json, sys, os, socket
from datetime import datetime
from collections import defaultdict

VIP          = '10.0.0.100'
NO_LB_TARGET = '10.0.0.1'          # Gửi thẳng đến h1, không qua VIP
SERVER_IPS   = ['10.0.0.1','10.0.0.2','10.0.0.3',
                '10.0.0.4','10.0.0.5','10.0.0.6']
SERVER_NAMES = ['h1','h2','h3','h4','h5','h6']

N_REQUESTS   = int(sys.argv[1]) if len(sys.argv) > 1 else 30
WAVE_SIZE    = 5
FILE_PATH    = '/tmp/testfile_10mb'   # File lớn để đo BW thực tế

# ── Tạo timestamp cho thư mục lưu kết quả ──
TIMESTAMP    = datetime.now().strftime('%Y%m%d_%H%M%S')
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
RESULT_DIR   = os.path.join(PROJECT_ROOT, 'visualize', 'results', TIMESTAMP)
os.makedirs(RESULT_DIR, exist_ok=True)
RESULT_FILE  = os.path.join(RESULT_DIR, 'benchmark_results.json')

lock    = threading.Lock()
results = {
    'with_lb':    {'dist': {}, 'latency': [], 'bw_runs': []},
    'without_lb': {'dist': {}, 'latency': [], 'bw_runs': []},
}

# ──────────────────────────────────────────────────────────
#  Tạo file test lớn trên h1..h6 (10MB)
# ──────────────────────────────────────────────────────────

def create_test_file():
    """Tạo file 10MB tại /tmp/testfile_10mb để server.py serve."""
    if not os.path.exists(FILE_PATH):
        print(f'[SETUP] Tạo file test 10MB tại {FILE_PATH}...')
        with open(FILE_PATH, 'wb') as f:
            f.write(os.urandom(10 * 1024 * 1024))
        print('[SETUP] Done.')
    else:
        print(f'[SETUP] File test đã tồn tại: {FILE_PATH}')

# ──────────────────────────────────────────────────────────
#  HTTP request — đo latency + detect server
# ──────────────────────────────────────────────────────────

def http_get_small(target_ip, timeout=5):
    """GET / — nhỏ, để đo latency và phân phối."""
    t0 = time.time()
    try:
        cmd = ['wget', '-qO-', f'http://{target_ip}/',
               '--timeout=4', '--tries=1']
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        lat = (time.time() - t0) * 1000
        body = out.decode('utf-8', errors='ignore')

        # Tìm server IP trong response
        for ip in SERVER_IPS:
            if ip in body:
                return ip, round(lat, 2), len(out)
        return 'unknown', round(lat, 2), len(out)
    except subprocess.TimeoutExpired:
        return 'timeout', 9999, 0
    except Exception:
        return 'error', 9999, 0

def http_get_large(target_ip, timeout=15):
    """GET /testfile_10mb — lớn, để đo bandwidth thực tế."""
    t0 = time.time()
    try:
        cmd = ['wget', '-qO-',
               f'http://{target_ip}/testfile_10mb',
               '--timeout=12', '--tries=1']
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        elapsed = time.time() - t0
        size_mb = len(out) / (1024 * 1024)
        bw_mbps = round((size_mb * 8) / elapsed, 2) if elapsed > 0 else 0
        return bw_mbps, round(elapsed * 1000, 1)
    except Exception:
        return 0.0, 9999

# ──────────────────────────────────────────────────────────
#  Test 1: Phân phối request + Latency
# ──────────────────────────────────────────────────────────

def run_distribution_test(target_ip, result_key, label, n):
    print(f"\n{'='*55}")
    print(f"[TEST] {label}")
    print(f"       Target: {target_ip} | Requests: {n}")
    print(f"{'='*55}")

    dist    = {}
    latency = []

    def worker():
        srv, lat, _ = http_get_small(target_ip)
        with lock:
            dist[srv]  = dist.get(srv, 0) + 1
            latency.append(lat)

    for i in range(0, n, WAVE_SIZE):
        batch = []
        for _ in range(min(WAVE_SIZE, n - i)):
            t = threading.Thread(target=worker)
            batch.append(t)
            t.start()
        for t in batch:
            t.join(timeout=10)
        done = min(i + WAVE_SIZE, n)
        print(f'  [{done:3d}/{n}] dist={dict(sorted(dist.items()))}')
        time.sleep(0.3)

    valid_lat = [l for l in latency if l < 9000]
    avg_lat   = round(sum(valid_lat)/len(valid_lat), 2) if valid_lat else 0
    max_lat   = round(max(valid_lat), 2)                if valid_lat else 0

    print(f'\n[RESULT] Distribution : {dict(sorted(dist.items()))}')
    print(f'[RESULT] Latency      : avg={avg_lat}ms  max={max_lat}ms')

    with lock:
        results[result_key]['dist']    = dist
        results[result_key]['latency'] = latency

    return dist, latency

# ──────────────────────────────────────────────────────────
#  Test 2: Bandwidth — dùng file 10MB
# ──────────────────────────────────────────────────────────

def run_bandwidth_test(target_ip, result_key, label, n_runs=5):
    print(f'\n[BW] {label} → {target_ip}  ({n_runs} lần đo file 10MB)')
    bw_list = []

    for i in range(n_runs):
        bw, ms = http_get_large(target_ip)
        bw_list.append(bw)
        status = f'{bw:.2f} Mbps  ({ms:.0f}ms)'
        print(f'  Run {i+1}/{n_runs}: {status}')
        time.sleep(0.5)

    valid = [b for b in bw_list if b > 0]
    avg   = round(sum(valid)/len(valid), 2) if valid else 0
    print(f'[BW] Average: {avg:.2f} Mbps')

    with lock:
        results[result_key]['bw_runs'] = bw_list
        results[result_key]['avg_bw']  = avg

    return avg

# ──────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────

def main():
    create_test_file()

    print('\n' + '='*60)
    print('  SDN Load Balancer Benchmark — Least Connection')
    print('='*60)
    print(f'  VIP         : {VIP}')
    print(f'  No-LB target: {NO_LB_TARGET} (h1 trực tiếp)')
    print(f'  N requests  : {N_REQUESTS}')
    print(f'  Results dir : {RESULT_DIR}')
    print('='*60)
    print()
    print('  QUAN TRỌNG: KHÔNG tắt Ryu trong suốt quá trình test!')
    print('  - Phase 1: request → VIP (có LB)')
    print('  - Phase 2: request → h1 trực tiếp (không LB, Ryu vẫn chạy)')
    print()
    input('  Nhấn Enter để bắt đầu...')

    t_start = time.time()

    # ── Phase 1: CÓ LB ──
    print('\n' + '─'*55)
    print('  PHASE 1: CÓ Load Balancing (VIP → Least Connection)')
    print('─'*55)
    dist_lb, lat_lb = run_distribution_test(
        VIP, 'with_lb', 'WITH LB — VIP 10.0.0.100', N_REQUESTS)

    print('\n[INFO] Đợi 2s để flow table ổn định...')
    time.sleep(2)

    bw_lb = run_bandwidth_test(VIP, 'with_lb', 'WITH LB bandwidth')

    # ── Phase 2: KHÔNG LB ──
    print('\n' + '─'*55)
    print('  PHASE 2: KHÔNG Load Balancing (thẳng → h1)')
    print('  (Ryu VẪN ĐANG CHẠY — chỉ bypass VIP)')
    print('─'*55)
    dist_nolb, lat_nolb = run_distribution_test(
        NO_LB_TARGET, 'without_lb',
        'WITHOUT LB — direct 10.0.0.1', N_REQUESTS)

    bw_nolb = run_bandwidth_test(
        NO_LB_TARGET, 'without_lb', 'WITHOUT LB bandwidth')

    # ── Tính toán kết quả ──
    valid_lb   = [l for l in lat_lb   if l < 9000]
    valid_nolb = [l for l in lat_nolb if l < 9000]

    avg_lat_lb   = round(sum(valid_lb)  /len(valid_lb),   2) if valid_lb   else 0
    avg_lat_nolb = round(sum(valid_nolb)/len(valid_nolb), 2) if valid_nolb else 0
    max_lat_lb   = round(max(valid_lb),  2) if valid_lb   else 0
    max_lat_nolb = round(max(valid_nolb),2) if valid_nolb else 0

    import numpy as np
    lb_counts   = [dist_lb.get(ip, 0)   for ip in SERVER_IPS]
    nolb_counts = [dist_nolb.get(ip, 0) for ip in SERVER_IPS]
    std_lb      = round(float(np.std(lb_counts)),   2)
    std_nolb    = round(float(np.std(nolb_counts)), 2)

    bw_imp = round((bw_lb - bw_nolb) / bw_nolb * 100, 1) if bw_nolb > 0 else 0

    summary = {
        'timestamp':   TIMESTAMP,
        'n_requests':  N_REQUESTS,
        'duration_s':  round(time.time() - t_start, 1),
        'with_lb': {
            'avg_latency_ms': avg_lat_lb,
            'max_latency_ms': max_lat_lb,
            'avg_bw_mbps':    bw_lb,
            'distribution':   dist_lb,
            'std_dev':        std_lb,
        },
        'without_lb': {
            'avg_latency_ms': avg_lat_nolb,
            'max_latency_ms': max_lat_nolb,
            'avg_bw_mbps':    bw_nolb,
            'distribution':   dist_nolb,
            'std_dev':        std_nolb,
        },
        'comparison': {
            'bw_improvement_pct':  bw_imp,
            'lat_improvement_ms':  round(avg_lat_nolb - avg_lat_lb, 2),
            'std_improvement':     round(std_nolb - std_lb, 2),
            'meets_bw_target':     25 <= bw_imp <= 50,
            'meets_lat_target':    avg_lat_lb <= 100,
        },
        'server_names': SERVER_NAMES,
        'server_ips':   SERVER_IPS,
    }

    final = {**results, 'summary': summary}

    with open(RESULT_FILE, 'w') as f:
        json.dump(final, f, indent=2)

    # Cũng lưu vào /tmp để plot_results.py đọc được
    with open('/tmp/benchmark_results.json', 'w') as f:
        json.dump(final, f, indent=2)

    print('\n' + '='*60)
    print('  BENCHMARK SUMMARY')
    print('='*60)
    print(f'  {"Metric":<28} {"Có LB":>10} {"Không LB":>10} {"Target":>10}')
    print(f'  {"-"*58}')
    print(f'  {"Avg latency (ms)":<28} {avg_lat_lb:>10.1f} {avg_lat_nolb:>10.1f} {"≤100ms":>10}')
    print(f'  {"Max latency (ms)":<28} {max_lat_lb:>10.1f} {max_lat_nolb:>10.1f} {"≤200ms":>10}')
    print(f'  {"Avg bandwidth (Mbps)":<28} {bw_lb:>10.2f} {bw_nolb:>10.2f} {"-":>10}')
    print(f'  {"BW improvement":<28} {f"+{bw_imp}%":>10} {"-":>10} {"25–35%":>10}')
    print(f'  {"Dist. std deviation":<28} {std_lb:>10.2f} {std_nolb:>10.2f} {"<1.5":>10}')
    print(f'  {"-"*58}')
    lat_ok = "✓ PASS" if avg_lat_lb <= 100 else "✗ FAIL"
    bw_ok  = "✓ PASS" if 25 <= bw_imp <= 50 else ("↑ ABOVE" if bw_imp > 50 else "↓ BELOW")
    print(f'  Latency  target (≤100ms): {lat_ok}')
    print(f'  Bandwidth target (25-35%): {bw_ok}  ({bw_imp}%)')
    print()
    print(f'  Results saved:')
    print(f'    {RESULT_FILE}')
    print(f'    /tmp/benchmark_results.json')
    print()
    print(f'  Vẽ biểu đồ:')
    print(f'    python3 visualize/plot_results.py {TIMESTAMP}')
    print('='*60)


if __name__ == '__main__':
    main()