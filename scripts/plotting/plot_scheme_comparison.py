
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

def plot_scheme_performance_comparison():
    """
    Generates a bar chart comparing latencies of different HE schemes.
    Corresponds to fig:scheme-comparison in the paper.
    """
    try:
        df = pd.read_csv(f'{BASE_PATH}/scheme_comparison.csv')
        
        # Prepare data for plotting
        plot_df = df.melt(id_vars='scheme', 
                          value_vars=['encrypt_per_reading_ms', 'decrypt_ms', 'add_per_op_ms'],
                          var_name='Operation', 
                          value_name='Time (ms)')
        
        operation_map = {
            'encrypt_per_reading_ms': 'Encrypt',
            'decrypt_ms': 'Decrypt',
            'add_per_op_ms': 'Add'
        }
        plot_df['Operation'] = plot_df['Operation'].map(operation_map)

        plt.figure(figsize=(12, 7))
        ax = sns.barplot(x='scheme', y='Time (ms)', hue='Operation', data=plot_df)
        
        ax.set_title('Per-Operation Latency Comparison Across HE Schemes')
        ax.set_xlabel('HE Scheme')
        ax.set_ylabel('Time (ms)')
        
        # Use a logarithmic scale if values are very different
        if plot_df['Time (ms)'].max() / plot_df[plot_df['Time (ms)'] > 0]['Time (ms)'].min() > 100:
            ax.set_yscale('log')
            ax.set_ylabel('Time (ms) - Log Scale')

        for p in ax.patches:
            height = p.get_height()
            if height > 0:
                ax.annotate(f'{height:.3f}', 
                            (p.get_x() + p.get_width() / 2., height),
                            ha='center', va='center', fontsize=8, color='black', 
                            xytext=(0, 9), textcoords='offset points', rotation=45)

        plt.legend(title='Operation')
        plt.savefig(f'{FIGURE_PATH}/scheme_comparison.png', bbox_inches='tight')
        plt.close()
        print("Generated scheme_comparison.png")

    except FileNotFoundError:
        print("scheme_comparison.csv not found. Skipping plot_scheme_performance_comparison.")


if __name__ == '__main__':
    plot_scheme_performance_comparison()
