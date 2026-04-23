
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# Set plot style
sns.set_theme(style="whitegrid")

# Define base path for data
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'output'))
FIGURE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'paper', 'figs'))

# Create figure directory if it doesn't exist
os.makedirs(FIGURE_PATH, exist_ok=True)

def plot_encryption_performance():
    """
    Generates a bar chart for average encryption and decryption times.
    Corresponds to fig:enc-dec-bar in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/encryption_metrics.csv')
        
        # Calculate average times
        avg_encrypt_time = df[df['operation'] == 'encrypt_vector']['value'].mean()
        avg_decrypt_time = df[df['operation'] == 'decrypt']['value'].mean()
        avg_batch_decrypt_time = df[df['operation'] == 'batch_decrypt']['value'].mean()
        
        data = {
            'Operation': ['Encrypt', 'Decrypt', 'Batch Decrypt'],
            'Average Time (ms)': [avg_encrypt_time, avg_decrypt_time, avg_batch_decrypt_time]
        }
        plot_df = pd.DataFrame(data)
        
        plt.figure(figsize=(8, 6))
        ax = sns.barplot(x='Operation', y='Average Time (ms)', data=plot_df)
        ax.set_title('Average Encryption and Decryption Times (100 Meters)')
        
        # Add values on top of bars
        for p in ax.patches:
            ax.annotate(f'{p.get_height():.2f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                        textcoords='offset points')
                        
        plt.savefig(f'{FIGURE_PATH}/enc_dec_bar.png', bbox_inches='tight')
        plt.close()
        print("Generated enc_dec_bar.png")

    except FileNotFoundError:
        print("encryption_metrics.csv not found. Skipping plot_encryption_performance.")


def plot_batch_sums():
    """
    Generates a bar chart of per-batch decrypted aggregation sums.
    Corresponds to fig:batch-sums in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/batch_analytics.csv')
        
        plt.figure(figsize=(12, 6))
        ax = sns.barplot(x='batch_id', y='decrypted_sum_kwh', data=df, color='skyblue')
        ax.set_title('Per-Batch Decrypted Aggregation Sums (100 Meters)')
        ax.set_xlabel('Batch ID')
        ax.set_ylabel('Decrypted Sum (kWh)')
        
        # Improve x-tick readability
        if len(df['batch_id']) > 20:
            ax.set_xticks(ax.get_xticks()[::5])
            plt.xticks(rotation=45)

        plt.savefig(f'{FIGURE_PATH}/batch_sums.png', bbox_inches='tight')
        plt.close()
        print("Generated batch_sums.png")

    except FileNotFoundError:
        print("batch_analytics.csv not found. Skipping plot_batch_sums.")


def plot_batch_sizes():
    """
    Generates a bar chart of the number of readings per batch.
    Corresponds to fig:batch-sizes in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/batch_analytics.csv')
        
        plt.figure(figsize=(12, 6))
        ax = sns.barplot(x='batch_id', y='num_readings', data=df, color='coral')
        ax.set_title('Number of Readings per Batch (100 Meters)')
        ax.set_xlabel('Batch ID')
        ax.set_ylabel('Readings per Batch')

        if len(df['batch_id']) > 20:
            ax.set_xticks(ax.get_xticks()[::5])
            plt.xticks(rotation=45)

        plt.savefig(f'{FIGURE_PATH}/batch_sizes.png', bbox_inches='tight')
        plt.close()
        print("Generated batch_sizes.png")

    except FileNotFoundError:
        print("batch_analytics.csv not found. Skipping plot_batch_sizes.")


if __name__ == '__main__':
    plot_encryption_performance()
    plot_batch_sums()
    plot_batch_sizes()
