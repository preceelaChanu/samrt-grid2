
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Set plot style
sns.set_theme(style="whitegrid")

# Define base path for data and figures
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'output'))
FIGURE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'paper', 'figs'))

# Create figure directory if it doesn't exist
os.makedirs(FIGURE_PATH, exist_ok=True)

METER_CONFIGS = [10, 50, 100, 500]

def load_scalability_data(metric_file, configs):
    """Loads and aggregates scalability data from benchmark directories."""
    all_data = []
    for n in configs:
        path = f'{BASE_PATH}/bench_{n}/{metric_file}'
        if os.path.exists(path):
            try:
                df = pd.read_csv(path, on_bad_lines='skip')
                df['meters'] = n
                all_data.append(df)
            except Exception as e:
                print(f"Could not read {path}: {e}")
    if not all_data:
        return pd.DataFrame()
    return pd.concat(all_data, ignore_index=True)

def plot_encryption_comparison():
    """
    Generates a bar chart comparing average encryption and decryption times across meter scales.
    Corresponds to fig:enc-comparison in the paper.
    """
    df = load_scalability_data('encryption_metrics.csv', METER_CONFIGS)
    if df.empty:
        print("No scalability data found for encryption. Skipping plot_encryption_comparison.")
        return

    encrypt_df = df[df['operation'] == 'encrypt_vector'].groupby('meters')['value'].mean().reset_index()
    decrypt_df = df[df['operation'] == 'decrypt'].groupby('meters')['value'].mean().reset_index()

    plot_df = pd.merge(encrypt_df, decrypt_df, on='meters', suffixes=('_encrypt', '_decrypt'))
    plot_df = plot_df.rename(columns={'value_encrypt': 'Avg Encrypt', 'value_decrypt': 'Avg Decrypt'})
    
    melted_df = plot_df.melt(id_vars='meters', var_name='Operation', value_name='Time (ms)')

    plt.figure(figsize=(10, 7))
    ax = sns.barplot(x='meters', y='Time (ms)', hue='Operation', data=melted_df)
    ax.set_title('Average Encryption and Decryption Times Across Meter Scales')
    ax.set_xlabel('Number of Smart Meters')
    ax.set_ylabel('Time (ms)')
    
    for p in ax.patches:
        ax.annotate(f'{p.get_height():.2f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', fontsize=9, color='black', xytext=(0, 5),
                    textcoords='offset points', rotation=30)

    plt.savefig(f'{FIGURE_PATH}/enc_comparison.png', bbox_inches='tight')
    plt.close()
    print("Generated enc_comparison.png")


def plot_batches_processed_comparison():
    """
    Generates a bar chart comparing total batches processed across meter scales.
    Corresponds to fig:batches-comparison in the paper.
    """
    batch_counts = []
    for n in METER_CONFIGS:
        path = f'{BASE_PATH}/bench_{n}/batch_analytics.csv'
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                batch_counts.append({'meters': n, 'batches': df['batch_id'].nunique()})
            except Exception as e:
                print(f"Could not process {path}: {e}")

    if not batch_counts:
        print("No batch analytics data found for scalability comparison. Skipping plot.")
        return

    plot_df = pd.DataFrame(batch_counts)

    plt.figure(figsize=(10, 6))
    ax = sns.barplot(x='meters', y='batches', data=plot_df)
    ax.set_title('Total Batches Processed During Fixed Benchmark Duration')
    ax.set_xlabel('Number of Smart Meters')
    ax.set_ylabel('Batches Processed')

    for p in ax.patches:
        ax.annotate(f'{int(p.get_height())}', (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                    textcoords='offset points')

    plt.savefig(f'{FIGURE_PATH}/batches_comparison.png', bbox_inches='tight')
    plt.close()
    print("Generated batches_comparison.png")


def plot_zkp_verification_comparison():
    """
    Generates a bar chart comparing average range proof verification times.
    Corresponds to fig:zkp-comparison in the paper.
    """
    df = load_scalability_data('security_metrics.csv', METER_CONFIGS)
    if df.empty:
        print("No scalability data for security metrics. Skipping ZKP comparison plot.")
        return
    
    # Note: 500-meter config logs generation time, not verification. Filter it out.
    verify_df = df[(df['operation'] == 'range_proof_verify') & (df['meters'] < 500)]
    avg_verify_time = verify_df.groupby('meters')['value'].mean().reset_index()

    plt.figure(figsize=(10, 6))
    ax = sns.barplot(x='meters', y='value', data=avg_verify_time)
    ax.set_title('Average Range Proof Verification Time Across Meter Scales')
    ax.set_xlabel('Number of Smart Meters')
    ax.set_ylabel('Average Time (ms)')

    for p in ax.patches:
        ax.annotate(f'{p.get_height():.3f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                    textcoords='offset points')

    plt.savefig(f'{FIGURE_PATH}/zkp_comparison.png', bbox_inches='tight')
    plt.close()
    print("Generated zkp_comparison.png")


def plot_network_connection_comparison():
    """
    Generates a bar chart comparing average client connection times across scales.
    Corresponds to fig:net-comparison in the paper.
    """
    df = load_scalability_data('network_metrics.csv', METER_CONFIGS)
    if df.empty:
        print("No scalability data for network metrics. Skipping network comparison plot.")
        return

    connect_df = df[df['operation'] == 'client_connect_time']
    avg_connect_time = (connect_df.groupby('meters')['value'].mean() / 1e6).reset_index()
    avg_connect_time.rename(columns={'value': 'Avg Connect Time (ms)'}, inplace=True)

    plt.figure(figsize=(10, 6))
    ax = sns.barplot(x='meters', y='Avg Connect Time (ms)', data=avg_connect_time)
    ax.set_title('Average Client Connection Time Across Meter Scales')
    ax.set_xlabel('Number of Smart Meters')
    ax.set_ylabel('Average Connect Time (ms)')

    for p in ax.patches:
        ax.annotate(f'{p.get_height():.2f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                    textcoords='offset points')

    plt.savefig(f'{FIGURE_PATH}/net_comparison.png', bbox_inches='tight')
    plt.close()
    print("Generated net_comparison.png")


if __name__ == '__main__':
    plot_encryption_comparison()
    plot_batches_processed_comparison()
    plot_zkp_verification_comparison()
    plot_network_connection_comparison()
