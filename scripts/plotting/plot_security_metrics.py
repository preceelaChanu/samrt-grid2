
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Set plot style
sns.set_theme(style="whitegrid")

# Define base path for data
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'output'))
FIGURE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'paper', 'figs'))

# Create figure directory if it doesn't exist
os.makedirs(FIGURE_PATH, exist_ok=True)

def plot_zkp_performance():
    """
    Generates a bar chart for average ZKP and verification operation times.
    Corresponds to fig:zkp-times in the paper.
    """
    try:
        df_sec = pd.read_csv(f'{BASE_PATH}/security_metrics.csv')
        df_theft = pd.read_csv(f'{BASE_PATH}/theft_detection.csv', on_bad_lines='skip')

        # Calculate average times
        avg_range_verify = df_sec[df_sec['operation'] == 'range_proof_verify']['value'].mean()
        avg_agg_proof_gen = df_sec[df_sec['operation'] == 'aggregation_proof_generate']['value'].mean()
        avg_verifiable_record = df_sec[df_sec['operation'] == 'verifiable_aggregation_record']['value'].mean()
        avg_theft_detect = df_sec[df_sec['operation'] == 'theft_detection']['value'].mean() if not df_sec.empty else 0

        data = {
            'Operation': ['Range Verify', 'Agg Proof Gen', 'Verifiable Record', 'Theft Detect'],
            'Average Time (ms)': [avg_range_verify, avg_agg_proof_gen, avg_verifiable_record, avg_theft_detect]
        }
        plot_df = pd.DataFrame(data)

        plt.figure(figsize=(10, 6))
        ax = sns.barplot(x='Operation', y='Average Time (ms)', data=plot_df)
        ax.set_title('Average ZKP and Verification Operation Times')
        plt.xticks(rotation=15, ha="right")

        for p in ax.patches:
            ax.annotate(f'{p.get_height():.3f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                        textcoords='offset points')

        plt.savefig(f'{FIGURE_PATH}/zkp_times.png', bbox_inches='tight')
        plt.close()
        print("Generated zkp_times.png")

    except FileNotFoundError:
        print("security_metrics.csv or theft_detection.csv not found. Skipping plot_zkp_performance.")


def plot_theft_detection_zscore():
    """
    Generates a plot of Z-scores for theft detection.
    Corresponds to fig:theft-zscore in the paper.
    """
    theft_file = os.path.join(BASE_PATH, 'theft_detection.csv')
    if not os.path.exists(theft_file):
        print(f"{theft_file} not found. Skipping plot.")
        return

    df = pd.read_csv(theft_file)
    if df.empty:
        print("theft_detection.csv is empty. Skipping plot.")
        return

    plt.figure(figsize=(12, 7))
    
    # Create a scatter plot of Z-scores
    sns.scatterplot(data=df, x=df.index, y='z_score', hue='is_anomalous', style='is_anomalous', s=100)
    
    plt.title('Theft Detection Z-Scores per Meter Reading')
    plt.xlabel('Meter Reading Index')
    plt.ylabel('Z-Score')
    
    # Add a threshold line
    plt.axhline(y=3, color='r', linestyle='--', label='Threshold (Z=3)')
    plt.axhline(y=-3, color='r', linestyle='--')
    
    plt.legend(title='Status')
    plt.tight_layout()
    
    save_path = os.path.join(FIGURE_PATH, 'theft_zscore.png')
    plt.savefig(save_path, bbox_inches='tight')
    print(f"Generated {os.path.basename(save_path)}")
    plt.close()


def plot_theft_detection_deviation():
    """
    Generates a bar chart of percentage deviation for anomalous meters.
    Corresponds to fig:theft-deviation in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/theft_detection.csv', on_bad_lines='skip')
        anomalies = df[df['is_anomalous'] == True]

        if anomalies.empty:
            print("No anomalies found in theft_detection.csv. Skipping plot_theft_detection_deviation.")
            return
            
        plt.figure(figsize=(8, 6))
        ax = sns.barplot(x=anomalies['meter_id'].astype(str), y=anomalies['deviation_percent'], order=anomalies['meter_id'].astype(str).unique())
        ax.set_xlabel('Anomalous Meter ID')
        ax.set_ylabel('Deviation from Peer Mean (%)')
        ax.set_title('Percentage Deviation for Detected Anomalous Meters')

        for p in ax.patches:
            ax.annotate(f'{p.get_height():.2f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                        textcoords='offset points')

        plt.savefig(f'{FIGURE_PATH}/theft_deviation.png', bbox_inches='tight')
        plt.close()
        print("Generated theft_deviation.png")

    except FileNotFoundError:
        print("theft_detection.csv not found. Skipping plot_theft_detection_deviation.")


if __name__ == "__main__":
    print("Generating security metrics plots...")
    plot_zkp_performance()
    plot_theft_detection_zscore()
