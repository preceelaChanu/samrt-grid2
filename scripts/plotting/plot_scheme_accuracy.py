
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np

# Set plot style
sns.set_theme(style="whitegrid")

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'output'))
figs_dir = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', 'paper', 'figs'))
os.makedirs(figs_dir, exist_ok=True)

def plot_scheme_accuracy():
    """
    Generates a bar chart comparing the accuracy of different HE schemes.
    Corresponds to fig:scheme-accuracy in the paper.
    """
    scheme_comp_file = os.path.join(output_dir, 'scheme_comparison.csv')
    if not os.path.exists(scheme_comp_file):
        print(f"{scheme_comp_file} not found. Skipping plot.")
        return

    df = pd.read_csv(scheme_comp_file)
    if df.empty:
        print("scheme_comparison.csv is empty. Skipping plot.")
        return

    df['log_rel_error'] = -np.log10(df['relative_error_pct'])

    plt.figure(figsize=(10, 6))
    ax = sns.barplot(x='scheme', y='log_rel_error', data=df)
    
    plt.title('HE Scheme Aggregation Accuracy (Lower is Better)')
    plt.xlabel('HE Scheme')
    plt.ylabel('Log Relative Error (-log10(%))')

    for p in ax.patches:
        height = p.get_height()
        original_error = 10**(-height)
        ax.annotate(f'{original_error:.2e}%', 
                    (p.get_x() + p.get_width() / 2., height),
                    ha='center', va='center', fontsize=9, color='black', xytext=(0, 5),
                    textcoords='offset points')

    save_path = os.path.join(figs_dir, 'scheme_accuracy.png')
    plt.savefig(save_path, bbox_inches='tight')
    print(f"Generated {os.path.basename(save_path)}")
    plt.close()

if __name__ == "__main__":
    print("Generating scheme accuracy plot...")
    plot_scheme_accuracy()
