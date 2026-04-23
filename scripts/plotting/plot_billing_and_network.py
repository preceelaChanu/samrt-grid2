
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

def plot_tou_billing_costs():
    """
    Generates a bar chart of per-meter billing costs.
    Corresponds to fig:tou-cost-dist in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/tou_billing.csv')
        
        # Assuming the CSV is for a single billing period
        df_sorted = df.sort_values(by='cost_pence')
        df_sorted['meter_id_str'] = df_sorted['meter_id'].astype(str)

        plt.figure(figsize=(14, 7))
        ax = sns.barplot(x='meter_id_str', y='cost_pence', data=df_sorted, color='purple')
        
        ax.set_title('Distribution of Per-Meter Billing Costs')
        ax.set_xlabel('Meter ID (sorted by consumption)')
        ax.set_ylabel('Billing Cost (pence)')

        # Improve x-tick readability
        if len(df_sorted['meter_id_str']) > 20:
            tick_positions = range(0, len(df_sorted['meter_id_str']), 10)
            tick_labels = [df_sorted['meter_id_str'].iloc[i] for i in tick_positions]
            ax.set_xticks(tick_positions)
            ax.set_xticklabels(tick_labels, rotation=45)
        else:
            plt.xticks(rotation=45)

        plt.savefig(f'{FIGURE_PATH}/tou_cost_dist.png', bbox_inches='tight')
        plt.close()
        print("Generated tou_cost_dist.png")

    except FileNotFoundError:
        print("tou_billing.csv not found. Skipping plot_tou_billing_costs.")


def plot_network_connection_times():
    """
    Generates a bar chart of initial connection times to system components.
    Corresponds to fig:network-connect in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/network_metrics.csv')
        
        # Filter for initial connection events
        connect_times = df[df['operation'] == 'client_connect']
        
        if connect_times.empty:
            print("No client connect time events found in network_metrics.csv. Skipping plot.")
            return

        data = {
            'Component': [row['metadata'].split(':')[0] for index, row in connect_times.iterrows()],
            'Initial Connect Time (ms)': [row['value'] / 1e6 for index, row in connect_times.iterrows()]
        }
        plot_df = pd.DataFrame(data)

        plt.figure(figsize=(8, 6))
        ax = sns.barplot(x='Component', y='Initial Connect Time (ms)', data=plot_df)
        ax.set_title('Initial Connection Times to System Components')

        for p in ax.patches:
            ax.annotate(f'{p.get_height():.2f}', (p.get_x() + p.get_width() / 2., p.get_height()),
                        ha='center', va='center', fontsize=10, color='black', xytext=(0, 5),
                        textcoords='offset points')

        plt.savefig(f'{FIGURE_PATH}/network_connect.png', bbox_inches='tight')
        plt.close()
        print("Generated network_connect.png")

    except FileNotFoundError:
        print("network_metrics.csv not found. Skipping plot_network_connection_times.")


if __name__ == '__main__':
    plot_tou_billing_costs()
    plot_network_connection_times()
