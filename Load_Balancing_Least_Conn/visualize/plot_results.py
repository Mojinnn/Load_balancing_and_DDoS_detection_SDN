#!/usr/bin/env python3
"""
Vẽ biểu đồ kết quả benchmark
Chạy trên máy thật (ngoài Mininet):
  python3 visualize/plot_results.py [timestamp]

Nếu không có timestamp → dùng kết quả mới nhất trong results/
"""

import json, sys, os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.ticker import MaxNLocator
from datetime import datetime
from glob import glob

# ── Tìm file kết quả ──
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
RESULTS_BASE = os.path.join(SCRIPT_DIR, 'results')

def find_result_file(timestamp=None):
    if timestamp:
        path = os.path.join(RESULTS_BASE, timestamp, 'benchmark_results.json')
        if os.path.exists(path):
            return path, timestamp
        print(f'[ERROR] Không tìm thấy: {path}')
        sys.exit(1)

    # Tìm kết quả mới nhất
    pattern = os.path.join(RESULTS_BASE, '*', 'benchmark_results.json')
    files   = sorted(glob(pattern), reverse=True)
    if files:
        ts = os.path.basename(os.path.dirname(files[0]))
        return files[0], ts

    # Fallback: /tmp
    if os.path.exists('/tmp/benchmark_results.json'):
        return '/tmp/benchmark_results.json', 'latest'

    return None, None

# ── Màu sắc ──
C_LB    = '#1D9E75'
C_NOLB  = '#D85A30'
C_GOLD  = '#BA7517'
C_PURPLE= '#7F77DD'
C_GRAY  = '#888780'
BG      = '#FAFAF8'
BG2     = '#F4F3F0'


def make_demo_data():
    """Demo data khi chưa có kết quả thực."""
    np.random.seed(42)
    srv_ips   = ['10.0.0.'+str(i) for i in range(1,7)]
    srv_names = ['h1','h2','h3','h4','h5','h6']

    lb_dist   = {ip: int(np.random.normal(5, 0.8)) for ip in srv_ips}
    nolb_dist = {'10.0.0.1': 30}

    return {
        'with_lb':    {
            'dist': lb_dist, 'avg_bw': 38.5,
            'latency': list(np.random.normal(28, 6, 30)),
            'bw_runs': list(np.random.normal(38.5, 2, 5)),
        },
        'without_lb': {
            'dist': nolb_dist, 'avg_bw': 28.2,
            'latency': list(np.random.normal(42, 10, 30)),
            'bw_runs': list(np.random.normal(28.2, 3, 5)),
        },
        'summary': {
            'with_lb':    {'avg_latency_ms':28.3,'max_latency_ms':61.2,
                           'avg_bw_mbps':38.5,'std_dev':0.75},
            'without_lb': {'avg_latency_ms':42.1,'max_latency_ms':95.4,
                           'avg_bw_mbps':28.2,'std_dev':12.2},
            'comparison': {'bw_improvement_pct':36.5,
                           'lat_improvement_ms':13.8,
                           'meets_bw_target':True,
                           'meets_lat_target':True},
            'server_names': srv_names,
            'server_ips':   srv_ips,
            'n_requests':   30,
        },
    }, 'demo'


def plot_main(data, timestamp, out_dir):
    """Biểu đồ chính — 6 panel so sánh."""
    s      = data.get('summary', {})
    s_lb   = s.get('with_lb', {})
    s_nolb = s.get('without_lb', {})
    cmp    = s.get('comparison', {})
    srv_names = s.get('server_names', ['h1','h2','h3','h4','h5','h6'])
    srv_ips   = s.get('server_ips',
                      ['10.0.0.'+str(i) for i in range(1,7)])

    dist_lb   = data.get('with_lb',    {}).get('dist', {})
    dist_nolb = data.get('without_lb', {}).get('dist', {})
    lat_lb    = [l for l in data.get('with_lb',   {}).get('latency',[]) if l<9000]
    lat_nolb  = [l for l in data.get('without_lb',{}).get('latency',[]) if l<9000]
    bw_lb_r   = data.get('with_lb',   {}).get('bw_runs', [])
    bw_nolb_r = data.get('without_lb',{}).get('bw_runs', [])

    lb_counts   = [dist_lb.get(ip,0)   for ip in srv_ips]
    nolb_counts = [dist_nolb.get(ip,0) for ip in srv_ips]
    bw_lb    = s_lb.get('avg_bw_mbps',   np.mean(bw_lb_r)   if bw_lb_r   else 0)
    bw_nolb  = s_nolb.get('avg_bw_mbps', np.mean(bw_nolb_r) if bw_nolb_r else 0)
    bw_imp   = cmp.get('bw_improvement_pct', 0)
    std_lb   = s_lb.get('std_dev',   np.std(lb_counts))
    std_nolb = s_nolb.get('std_dev', np.std(nolb_counts))
    avg_lb   = s_lb.get('avg_latency_ms',   np.mean(lat_lb)   if lat_lb   else 0)
    avg_nolb = s_nolb.get('avg_latency_ms', np.mean(lat_nolb) if lat_nolb else 0)

    fig = plt.figure(figsize=(17, 12))
    fig.patch.set_facecolor(BG)
    gs  = gridspec.GridSpec(2, 3, figure=fig,
                            hspace=0.48, wspace=0.35,
                            top=0.88, bottom=0.07)

    meets_bw  = cmp.get('meets_bw_target',  False)
    meets_lat = cmp.get('meets_lat_target', False)

    fig.suptitle(
        f'SDN Load Balancer — Least Connection Algorithm\n'
        f'BW +{bw_imp:.1f}%  |  Latency cải thiện {cmp.get("lat_improvement_ms",0):.1f}ms'
        f'  |  {timestamp}',
        fontsize=14, fontweight='bold', color='#2C2C2A', y=0.95)

    x = np.arange(len(srv_names))
    w = 0.35

    # ── [0,0] Phân phối request ──
    ax1 = fig.add_subplot(gs[0, 0])
    b1  = ax1.bar(x-w/2, lb_counts,   w, color=C_LB,   label='Có LB',    zorder=3)
    b2  = ax1.bar(x+w/2, nolb_counts, w, color=C_NOLB, label='Không LB', zorder=3)
    avg_ideal = sum(lb_counts)/len(lb_counts) if lb_counts else 0
    ax1.axhline(avg_ideal, color=C_LB, ls='--', lw=1.2, alpha=0.7, label='Avg LB')
    ax1.set_title('Phân phối request theo server', fontweight='bold')
    ax1.set_xlabel('Server')
    ax1.set_ylabel('Số request')
    ax1.set_xticks(x); ax1.set_xticklabels(srv_names)
    ax1.legend(fontsize=8)
    ax1.bar_label(b1, padding=2, fontsize=9)
    ax1.bar_label(b2, padding=2, fontsize=9)
    ax1.grid(axis='y', alpha=0.3, zorder=0)
    ax1.set_facecolor(BG2)

    # ── [0,1] Bandwidth comparison ──
    ax2 = fig.add_subplot(gs[0, 1])
    cats = ['Có LB\n(Least Conn)', 'Không LB\n(direct h1)']
    bws  = [bw_lb, bw_nolb]
    bars = ax2.bar(cats, bws, color=[C_LB, C_NOLB], width=0.45, zorder=3)
    ax2.bar_label(bars, fmt='%.2f Mbps', padding=5, fontsize=10, fontweight='bold')

    # Target zone 25-35%
    if bw_nolb > 0:
        t_lo = bw_nolb * 1.25
        t_hi = bw_nolb * 1.35
        ax2.axhspan(t_lo, t_hi, alpha=0.18, color=C_GOLD,
                    label=f'Target zone (+25–35%)')
    ax2.set_title('Băng thông trung bình', fontweight='bold')
    ax2.set_ylabel('Mbps')
    ax2.set_ylim(0, max(bws)*1.35 if bws else 10)
    ax2.legend(fontsize=8)
    ax2.grid(axis='y', alpha=0.3, zorder=0)
    ax2.set_facecolor(BG2)

    # Mũi tên improvement
    if bw_nolb > 0:
        ax2.annotate(
            f'+{bw_imp:.1f}%',
            xy=(0, bw_lb), xytext=(0.5, (bw_lb+bw_nolb)/2),
            arrowprops=dict(arrowstyle='->', color=C_LB, lw=2),
            fontsize=13, color=C_LB, fontweight='bold', ha='center')

    # ── [0,2] Latency boxplot ──
    ax3 = fig.add_subplot(gs[0, 2])
    if lat_lb and lat_nolb:
        bp = ax3.boxplot(
            [lat_lb, lat_nolb],
            labels=['Có LB', 'Không LB'],
            patch_artist=True,
            medianprops=dict(color='white', linewidth=2.5),
            whiskerprops=dict(linewidth=1.3),
            capprops=dict(linewidth=1.3),
        )
        bp['boxes'][0].set_facecolor(C_LB)
        bp['boxes'][1].set_facecolor(C_NOLB)
    ax3.axhline(100, color='red', ls='--', lw=1.8,
                label='Target 100ms', zorder=5)
    ax3.set_title('Phân phối độ trễ', fontweight='bold')
    ax3.set_ylabel('Latency (ms)')
    ax3.legend(fontsize=9)
    ax3.grid(axis='y', alpha=0.3)
    ax3.set_facecolor(BG2)

    # ── [1,0] Std deviation ──
    ax4 = fig.add_subplot(gs[1, 0])
    b = ax4.bar(['Có LB', 'Không LB'], [std_lb, std_nolb],
                color=[C_LB, C_NOLB], width=0.4, zorder=3)
    ax4.bar_label(b, fmt='%.2f', padding=4, fontsize=12, fontweight='bold')
    ax4.set_title('Độ lệch chuẩn phân phối\n(thấp = đều hơn)', fontweight='bold')
    ax4.set_ylabel('Std deviation (requests)')
    ax4.grid(axis='y', alpha=0.3, zorder=0)
    ax4.set_facecolor(BG2)
    if std_lb < std_nolb:
        ax4.annotate('Đều hơn ↓', xy=(0, std_lb+0.05),
                     fontsize=10, color=C_LB, ha='center', fontweight='bold')

    # ── [1,1] Latency CDF ──
    ax5 = fig.add_subplot(gs[1, 1])
    for lat_data, color, label in [
        (lat_lb,   C_LB,   'Có LB'),
        (lat_nolb, C_NOLB, 'Không LB'),
    ]:
        if lat_data:
            sd  = np.sort(lat_data)
            cdf = np.arange(1, len(sd)+1) / len(sd)
            ax5.plot(sd, cdf, color=color, lw=2.5, label=label)
    ax5.axvline(100, color='red', ls='--', lw=1.8, label='100ms')
    ax5.set_title('CDF Độ trễ', fontweight='bold')
    ax5.set_xlabel('Latency (ms)')
    ax5.set_ylabel('Tỉ lệ tích lũy')
    ax5.legend(fontsize=9)
    ax5.grid(alpha=0.3)
    ax5.set_facecolor(BG2)

    # ── [1,2] Scorecard ──
    ax6 = fig.add_subplot(gs[1, 2])
    ax6.axis('off')

    rows = [
        ['Metric',              'Có LB',            'Không LB',         'Target'],
        ['Avg latency (ms)',    f'{avg_lb:.1f}',     f'{avg_nolb:.1f}',  '≤ 100ms'],
        ['Max latency (ms)',    f'{s_lb.get("max_latency_ms",0):.1f}',
                                f'{s_nolb.get("max_latency_ms",0):.1f}','≤ 200ms'],
        ['Avg BW (Mbps)',       f'{bw_lb:.2f}',      f'{bw_nolb:.2f}',   '—'],
        ['BW improvement',      f'+{bw_imp:.1f}%',   '—',                '25–35%'],
        ['Dist. std dev',       f'{std_lb:.2f}',     f'{std_nolb:.2f}',  '< 2.0'],
        ['N requests',          str(s.get('n_requests',0)),
                                str(s.get('n_requests',0)),              '—'],
    ]

    tbl = ax6.table(cellText=rows[1:], colLabels=rows[0],
                    loc='center', cellLoc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1.0, 1.7)

    for j in range(4):
        tbl[0,j].set_facecolor('#3C3489')
        tbl[0,j].set_text_props(color='white', fontweight='bold')

    # Tô màu row latency
    tbl[1,1].set_facecolor(C_LB   if meets_lat else '#F09595')
    tbl[1,3].set_facecolor('#FAC775')
    # Tô màu row BW
    tbl[4,1].set_facecolor(C_LB   if meets_bw  else '#F09595')
    tbl[4,3].set_facecolor('#FAC775')

    ax6.set_title('Scorecard', fontweight='bold', pad=14)

    badge_bw  = '✓ PASS' if meets_bw  else '✗ BELOW TARGET'
    badge_lat = '✓ PASS' if meets_lat else '✗ FAIL'
    ax6.text(0.25, 0.01, f'Latency: {badge_lat}',
             transform=ax6.transAxes, fontsize=10,
             color=C_LB if meets_lat else C_NOLB,
             fontweight='bold', ha='center')
    ax6.text(0.75, 0.01, f'BW: {badge_bw}',
             transform=ax6.transAxes, fontsize=10,
             color=C_LB if meets_bw else C_NOLB,
             fontweight='bold', ha='center')

    out_path = os.path.join(out_dir, 'comparison.png')
    plt.savefig(out_path, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f'[PLOT] Saved: {out_path}')
    return out_path


def plot_bw_detail(data, timestamp, out_dir):
    """Biểu đồ chi tiết bandwidth từng lần đo."""
    bw_lb_r   = data.get('with_lb',   {}).get('bw_runs', [])
    bw_nolb_r = data.get('without_lb',{}).get('bw_runs', [])

    if not bw_lb_r and not bw_nolb_r:
        return

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.patch.set_facecolor(BG)
    fig.suptitle(f'Bandwidth Detail — {timestamp}',
                 fontsize=13, fontweight='bold')

    # ── BW runs ──
    ax = axes[0]
    if bw_lb_r:
        ax.plot(range(1, len(bw_lb_r)+1), bw_lb_r,
                color=C_LB, marker='o', lw=2, ms=8, label='Có LB')
        ax.axhline(np.mean(bw_lb_r), color=C_LB, ls='--',
                   lw=1.2, alpha=0.6, label=f'Avg {np.mean(bw_lb_r):.2f} Mbps')
    if bw_nolb_r:
        ax.plot(range(1, len(bw_nolb_r)+1), bw_nolb_r,
                color=C_NOLB, marker='s', lw=2, ms=8, label='Không LB')
        ax.axhline(np.mean(bw_nolb_r), color=C_NOLB, ls='--',
                   lw=1.2, alpha=0.6, label=f'Avg {np.mean(bw_nolb_r):.2f} Mbps')

    # Target zone
    if bw_nolb_r:
        avg_nolb = np.mean(bw_nolb_r)
        ax.axhspan(avg_nolb*1.25, avg_nolb*1.35, alpha=0.15,
                   color=C_GOLD, label='Target +25–35%')

    ax.set_title('Bandwidth per run (file 10MB)', fontweight='bold')
    ax.set_xlabel('Lần đo')
    ax.set_ylabel('Mbps')
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    ax.set_facecolor(BG2)

    # ── Violin/bar so sánh ──
    ax2 = axes[1]
    data_for_violin = []
    labels_v = []
    if bw_lb_r:
        data_for_violin.append(bw_lb_r)
        labels_v.append('Có LB')
    if bw_nolb_r:
        data_for_violin.append(bw_nolb_r)
        labels_v.append('Không LB')

    if data_for_violin:
        vp = ax2.violinplot(data_for_violin, showmeans=True,
                            showmedians=True)
        colors_v = [C_LB, C_NOLB]
        for i, body in enumerate(vp['bodies']):
            body.set_facecolor(colors_v[i])
            body.set_alpha(0.7)
        ax2.set_xticks(range(1, len(labels_v)+1))
        ax2.set_xticklabels(labels_v)

    ax2.set_title('Phân phối bandwidth', fontweight='bold')
    ax2.set_ylabel('Mbps')
    ax2.grid(axis='y', alpha=0.3)
    ax2.set_facecolor(BG2)

    plt.tight_layout()
    out_path = os.path.join(out_dir, 'bandwidth_detail.png')
    plt.savefig(out_path, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f'[PLOT] Saved: {out_path}')


def main():
    timestamp = sys.argv[1] if len(sys.argv) > 1 else None
    result_file, ts = find_result_file(timestamp)

    use_demo = False
    if not result_file:
        print('[PLOT] Không có kết quả thực — dùng demo data')
        data, ts = make_demo_data()
        use_demo = True
    else:
        print(f'[PLOT] Đọc: {result_file}')
        with open(result_file) as f:
            data = json.load(f)

    # Thư mục output
    if not use_demo:
        result_dir = os.path.dirname(result_file)
    else:
        result_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'results', 'demo')
        os.makedirs(result_dir, exist_ok=True)

    print(f'[PLOT] Output dir: {result_dir}')

    plot_main(data, ts, result_dir)
    plot_bw_detail(data, ts, result_dir)

    print('\n[DONE] Biểu đồ đã lưu vào:')
    print(f'  {result_dir}/comparison.png')
    print(f'  {result_dir}/bandwidth_detail.png')

    if use_demo:
        print('\n[NOTE] Đây là demo data. Chạy benchmark thực tế:')
        print('  mininet> c1 python3 benchmark/run_benchmark.py 30')


if __name__ == '__main__':
    main()