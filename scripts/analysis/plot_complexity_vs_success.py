"""
Creates scatter plot comparing function complexity with decompilation success rate.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

COMPLEXITY_FILE = "function_complexity.csv"
PASS_FAIL_FILE = "pass_fail_results.csv"
OUTPUT_PLOT_FILE = "complexity_vs_success.png"

def create_plot():
    """
    Merges complexity and success data to create visualization.
    Args:
        :return: None. Saves plot to OUTPUT_PLOT_FILE.
    """
    try:
        df_complexity = pd.read_csv(COMPLEXITY_FILE)
        df_results = pd.read_csv(PASS_FAIL_FILE)
        df_merged = pd.merge(df_complexity, df_results, on=["binary", "function"])

        plt.figure(figsize=(12, 7))
        sns.stripplot(
            data=df_merged,
            x='cyclomatic_complexity', 
            y='pass', 
            jitter=0.2, 
            alpha=0.6,
            orient='h'
        )

        plt.yticks([0, 1], ['Fail', 'Pass'])
        plt.xlabel('Cyclomatic Complexity of Function')
        plt.ylabel('Decompilation Result')
        plt.title('Success Rate vs. Cyclomatic Complexity')
        plt.grid(axis='x', linestyle='--')
        
        plt.savefig(OUTPUT_PLOT_FILE)
        print(f"Scatter plot saved to: {OUTPUT_PLOT_FILE}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    create_plot()