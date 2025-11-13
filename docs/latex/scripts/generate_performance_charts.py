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
    'font.family': 'serif',
    'font.serif': ['Times', 'Computer Modern Roman'],
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
        results['password_registration_total']['mean'],
        results['fido2_registration_total']['mean'],
        results['totp_setup_total']['mean']
    ]
    errors_low = [
        results['password_registration_total']['mean'] - results['password_registration_total']['min'],
        results['fido2_registration_total']['mean'] - results['fido2_registration_total']['min'],
        results['totp_setup_total']['mean'] - results['totp_setup_total']['min']
    ]
    errors_high = [
        results['password_registration_total']['max'] - results['password_registration_total']['mean'],
        results['fido2_registration_total']['max'] - results['fido2_registration_total']['mean'],
        results['totp_setup_total']['max'] - results['totp_setup_total']['mean']
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
        results['password_login_total']['mean'],
        results['totp_login_total']['mean'],
        results['fido2_login_total']['mean']
    ]
    errors_low = [
        results['password_login_total']['mean'] - results['password_login_total']['min'],
        results['totp_login_total']['mean'] - results['totp_login_total']['min'],
        results['fido2_login_total']['mean'] - results['fido2_login_total']['min']
    ]
    errors_high = [
        results['password_login_total']['max'] - results['password_login_total']['mean'],
        results['totp_login_total']['max'] - results['totp_login_total']['mean'],
        results['fido2_login_total']['max'] - results['fido2_login_total']['mean']
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
    components = ['Start', 'WebAuthn\nCreate', 'Finish']
    values = [
        results['fido2_register_start']['mean'],
        results['fido2_webauthn_create']['mean'],
        results['fido2_register_finish']['mean']
    ]
    colors = [COLORS['fido2_start'], COLORS['fido2_webauthn'], COLORS['fido2_finish']]
    
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

def main():
    """Generate all performance charts."""
    print("Loading results...")
    results = load_results()
    
    print("Generating charts...")
    create_registration_comparison(results)
    create_login_comparison(results)
    create_fido2_breakdown(results)
    
    print("\nAll charts generated successfully!")
    print(f"Output directory: {FIGURES_DIR}")

if __name__ == '__main__':
    main()

