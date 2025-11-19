#!/usr/bin/env python3
"""
Generate performance comparison charts from latency test results.
Creates IEEE-style figures for LaTeX inclusion.
"""
import json
import matplotlib
matplotlib.use('PDF')  # Use PDF backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

# IEEE-style configuration
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['DejaVu Sans', 'Arial', 'Helvetica'],
    'font.size': 10,
    'axes.labelsize': 10,
    'axes.titlesize': 11,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.titlesize': 12,
    'text.usetex': False,  # Set to True if LaTeX is installed
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.format': 'pdf',
    'savefig.bbox': 'tight',
})

# Color scheme
COLORS = {
    'password': '#d62728',  # Red
    'totp': '#2ca02c',      # Green
    'fido2': '#1f77b4',     # Blue
    'fido2_start': '#8c564b',    # Brown
    'fido2_webauthn': '#ff7f0e', # Orange
    'fido2_finish': '#9467bd',  # Purple
}

# Figure output directory
FIGURES_DIR = Path(__file__).parent.parent / 'figures'
FIGURES_DIR.mkdir(exist_ok=True)

def load_results():
    """Load results from JSON file."""
    # Go up from scripts/ -> latex/ -> docs/ -> project root -> backend/
    script_dir = Path(__file__).parent
    results_file = script_dir.parent.parent.parent / 'backend' / 'results.json'
    if not results_file.exists():
        # Try alternative path
        results_file = script_dir.parent.parent.parent / 'backend' / 'test_results.json'
    with open(results_file, 'r') as f:
        return json.load(f)

def create_registration_comparison(results):
    """Create bar chart comparing registration/setup latencies."""
    fig, ax = plt.subplots(figsize=(4.5, 2.5))
    
    methods = ['Password', 'FIDO2', 'TOTP']
    means = [
        results.get('password_registration_total', {}).get('mean', 0),
        results.get('fido2_registration_total', {}).get('mean', 0),
        results.get('totp_setup_total', {}).get('mean', 0)
    ]
    errors_low = [
        means[0] - results.get('password_registration_total', {}).get('min', 0) if means[0] > 0 else 0,
        means[1] - results.get('fido2_registration_total', {}).get('min', 0) if means[1] > 0 else 0,
        means[2] - results.get('totp_setup_total', {}).get('min', 0) if means[2] > 0 else 0
    ]
    errors_high = [
        results.get('password_registration_total', {}).get('max', 0) - means[0] if means[0] > 0 else 0,
        results.get('fido2_registration_total', {}).get('max', 0) - means[1] if means[1] > 0 else 0,
        results.get('totp_setup_total', {}).get('max', 0) - means[2] if means[2] > 0 else 0
    ]
    
    bars = ax.bar(methods, means, 
                  color=[COLORS['password'], COLORS['fido2'], COLORS['totp']],
                  yerr=[errors_low, errors_high],
                  capsize=5,
                  alpha=0.8)
    
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Registration/Setup Latency Comparison')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add value labels on bars
    for bar, mean in zip(bars, means):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{mean:.1f}',
                ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'registration-latency-comparison.pdf')
    plt.close()
    print(f"Generated: {FIGURES_DIR / 'registration-latency-comparison.pdf'}")

def create_login_comparison(results):
    """Create bar chart comparing login latencies."""
    fig, ax = plt.subplots(figsize=(4.5, 2.5))
    
    methods = ['Password', 'TOTP', 'FIDO2']
    means = [
        results.get('password_login_total', {}).get('mean', 0),
        results.get('totp_login_total', {}).get('mean', 0),
        results.get('fido2_login_total', {}).get('mean', 0)
    ]
    errors_low = [
        means[0] - results.get('password_login_total', {}).get('min', 0) if means[0] > 0 else 0,
        means[1] - results.get('totp_login_total', {}).get('min', 0) if means[1] > 0 else 0,
        means[2] - results.get('fido2_login_total', {}).get('min', 0) if means[2] > 0 else 0
    ]
    errors_high = [
        results.get('password_login_total', {}).get('max', 0) - means[0] if means[0] > 0 else 0,
        results.get('totp_login_total', {}).get('max', 0) - means[1] if means[1] > 0 else 0,
        results.get('fido2_login_total', {}).get('max', 0) - means[2] if means[2] > 0 else 0
    ]
    
    bars = ax.bar(methods, means,
                  color=[COLORS['password'], COLORS['totp'], COLORS['fido2']],
                  yerr=[errors_low, errors_high],
                  capsize=5,
                  alpha=0.8)
    
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Login Latency Comparison')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add value labels on bars
    for bar, mean in zip(bars, means):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{mean:.1f}',
                ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'login-latency-comparison.pdf')
    plt.close()
    print(f"Generated: {FIGURES_DIR / 'login-latency-comparison.pdf'}")

def create_fido2_breakdown(results):
    """Create stacked bar chart showing FIDO2 registration breakdown."""
    fig, ax = plt.subplots(figsize=(3.5, 2.5))
    
    # Components of FIDO2 registration
    components = ['Start', 'Finish']
    values = [
        results.get('fido2_register_start', {}).get('mean', 0),
        results.get('fido2_register_finish', {}).get('mean', 0)
    ]
    colors = [COLORS['fido2_start'], COLORS['fido2_finish']]
    
    bars = ax.bar(['FIDO2\nRegistration'], [sum(values)],
                  color=COLORS['fido2'], alpha=0.3)
    
    # Create stacked segments
    bottom = 0
    for i, (comp, val, color) in enumerate(zip(components, values, colors)):
        ax.bar(['FIDO2\nRegistration'], [val],
               bottom=bottom, label=comp, color=color, alpha=0.8)
        # Add percentage label
        if val > 5:  # Only label if segment is large enough
            ax.text(0, bottom + val/2, f'{val:.1f}ms',
                   ha='center', va='center', fontsize=8, color='white', weight='bold')
        bottom += val
    
    ax.set_ylabel('Latency (ms)')
    ax.set_title('FIDO2 Registration Breakdown')
    ax.legend(loc='upper right', framealpha=0.9)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'fido2-registration-breakdown.pdf')
    plt.close()
    print(f"Generated: {FIGURES_DIR / 'fido2-registration-breakdown.pdf'}")

def create_resource_intensity_charts(results):
    """Create charts for resource intensity metrics (CPU, memory, DB queries).
    Uses backend-only measurements, excluding end-to-end/client-side operations."""
    # Check if we have any data
    if not results:
        print("WARNING: results.json is empty. Please run the latency tests first:")
        print("  cd backend && ./run_tests.sh tests/test_latency_*.py")
        return
    
    # CPU Time Comparison - Backend operations only
    fig, ax = plt.subplots(figsize=(4.5, 2.5))
    
    methods = ['Password', 'FIDO2', 'TOTP']
    
    # For FIDO2, combine start + finish (backend operations only, excludes client-side credential generation)
    fido2_reg_start_cpu = results.get('fido2_registration_start_cpu_ms', {}).get('mean', 0)
    fido2_reg_finish_cpu = results.get('fido2_registration_finish_cpu_ms', {}).get('mean', 0)
    fido2_reg_cpu = fido2_reg_start_cpu + fido2_reg_finish_cpu if (fido2_reg_start_cpu > 0 or fido2_reg_finish_cpu > 0) else results.get('fido2_registration_total_cpu_ms', {}).get('mean', 0)
    
    cpu_times = [
        results.get('password_registration_total_cpu_ms', {}).get('mean', 0),
        fido2_reg_cpu,
        results.get('totp_setup_total_cpu_ms', {}).get('mean', 0)
    ]
    
    # Check if all values are zero (no data)
    if all(v == 0 for v in cpu_times):
        print("WARNING: No CPU time data found. Make sure latency tests have been run.")
        print("  Expected keys: password_registration_total_cpu_ms, fido2_registration_start_cpu_ms, etc.")
    
    bars = ax.bar(methods, cpu_times,
                  color=[COLORS['password'], COLORS['fido2'], COLORS['totp']],
                  alpha=0.8)
    
    ax.set_ylabel('CPU Time (ms)')
    ax.set_title('Registration/Setup CPU Time Comparison')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Set y-axis minimum to 0, but allow it to scale if there's data
    if any(v > 0 for v in cpu_times):
        ax.set_ylim(bottom=0)
    else:
        # If no data, set a small range so bars are visible
        ax.set_ylim(0, 1)
        ax.text(0.5, 0.5, 'No data available\nRun latency tests first', 
                ha='center', va='center', transform=ax.transAxes, fontsize=10, 
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    for bar, val in zip(bars, cpu_times):
        if val > 0:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{val:.1f}',
                    ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'cpu-time-comparison.pdf')
    plt.close()
    print(f"Generated: {FIGURES_DIR / 'cpu-time-comparison.pdf'}")
    
    # Database Query Count Comparison - Backend operations only
    fig, ax = plt.subplots(figsize=(4.5, 2.5))
    
    # For FIDO2, combine start + finish (backend operations only)
    fido2_reg_start_db = results.get('fido2_registration_start_db_queries', {}).get('mean', 0)
    fido2_reg_finish_db = results.get('fido2_registration_finish_db_queries', {}).get('mean', 0)
    fido2_reg_db = fido2_reg_start_db + fido2_reg_finish_db if (fido2_reg_start_db > 0 or fido2_reg_finish_db > 0) else results.get('fido2_registration_total_db_queries', {}).get('mean', 0)
    
    db_queries = [
        results.get('password_registration_total_db_queries', {}).get('mean', 0),
        fido2_reg_db,
        results.get('totp_setup_total_db_queries', {}).get('mean', 0)
    ]
    
    bars = ax.bar(methods, db_queries,
                  color=[COLORS['password'], COLORS['fido2'], COLORS['totp']],
                  alpha=0.8)
    
    ax.set_ylabel('Database Queries')
    ax.set_title('Registration/Setup Database Query Count')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    for bar, val in zip(bars, db_queries):
        if val > 0:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{val:.0f}',
                    ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'db-queries-comparison.pdf')
    plt.close()
    print(f"Generated: {FIGURES_DIR / 'db-queries-comparison.pdf'}")
    
    # Memory Usage Comparison - Backend operations only
    fig, ax = plt.subplots(figsize=(4.5, 2.5))
    
    # For FIDO2, combine start + finish (backend operations only)
    fido2_reg_start_mem = results.get('fido2_registration_start_memory_mb', {}).get('mean', 0)
    fido2_reg_finish_mem = results.get('fido2_registration_finish_memory_mb', {}).get('mean', 0)
    fido2_reg_mem = fido2_reg_start_mem + fido2_reg_finish_mem if (fido2_reg_start_mem > 0 or fido2_reg_finish_mem > 0) else results.get('fido2_registration_total_memory_mb', {}).get('mean', 0)
    
    memory_deltas = [
        results.get('password_registration_total_memory_mb', {}).get('mean', 0),
        fido2_reg_mem,
        results.get('totp_setup_total_memory_mb', {}).get('mean', 0)
    ]
    
    bars = ax.bar(methods, memory_deltas,
                  color=[COLORS['password'], COLORS['fido2'], COLORS['totp']],
                  alpha=0.8)
    
    ax.set_ylabel('Memory Delta (MB)')
    ax.set_title('Registration/Setup Memory Usage')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    for bar, val in zip(bars, memory_deltas):
        if val > 0:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{val:.2f}',
                    ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'memory-usage-comparison.pdf')
    plt.close()
    print(f"Generated: {FIGURES_DIR / 'memory-usage-comparison.pdf'}")

def main():
    """Generate all performance charts."""
    print("Loading results...")
    results = load_results()
    
    print("Generating latency charts...")
    create_registration_comparison(results)
    create_login_comparison(results)
    create_fido2_breakdown(results)
    
    print("\nGenerating resource intensity charts...")
    create_resource_intensity_charts(results)
    
    print("\nAll charts generated successfully!")
    print(f"Output directory: {FIGURES_DIR}")

if __name__ == '__main__':
    main()

