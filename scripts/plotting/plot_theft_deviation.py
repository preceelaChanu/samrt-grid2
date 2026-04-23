
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

def plot_theft_deviation():
    """
    Generates a bar chart of percentage deviation for detected anomalous meters.
    Corresponds to fig:theft-deviation in the paper.
    """
    theft_file = os.path.join(BASE_PATH, 'theft_detection.csv')
    if not os.path.exists(theft_file):
        print(f"{theft_file} not found. Skipping plot.")
        return

    df = pd.read_csv(theft_file)
    anomalies = df[df['is_anomalous'] == True]

    if anomalies.empty:
        print("No anomalies found in theft_detection.csv. Skipping plot.")
        return

    plt.figure(figsize=(8, 6))
    ax = sns.barplot(x=anomalies['meter_id'].astype(str), y=anomalies['deviation_pct'])
    ax.set_xlabel('Anomalous Meter ID')
    ax.set_ylabel('Deviation from Peer Mean (%)')
    ax.set_title('Percentage Deviation for Detected Anomalous Meters')

    for p in ax.patches:
        ax.annotate(f'{p.get_height():.2f}%', (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                    textcoords='offset points')

    save_path = os.path.join(FIGURE_PATH, 'theft_deviation.png')
    plt.savefig(save_path, bbox_inches='tight')
    plt.close()
    print(f"Generated {os.path.basename(save_path)}")

if __name__ == '__main__':
    print("Generating theft deviation plot...")
    plot_theft_deviation()
