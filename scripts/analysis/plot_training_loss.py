"""
Reads loss_data.txt (written by train_final.py each epoch) and plots
training loss + validation loss on a single chart. Marks the epoch
where the tokenizer fix was applied so we can see the jump.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import matplotlib.pyplot as plt
import numpy as np

LOSS_FILE = "loss_data.txt"

def plot_loss_curve():
    """
    Creates and saves training and validation loss visualization plot.
    Args:
        :return: None. Saves plot to file.
    """
    try:
        data = np.loadtxt(LOSS_FILE, delimiter=',')
        train_loss = data[:, 0]
        eval_loss = data[:, 1]
        epochs = range(1, len(train_loss) + 1)

        plt.figure(figsize=(10, 6))
        plt.plot(epochs, train_loss, 'b-o', label='Training Loss')
        plt.plot(epochs, eval_loss, 'r-o', label='Validation Loss')
        
        plt.axvline(x=27.5, color='g', linestyle='--', label='Tokenizer & Weight Tying Fix')
        
        plt.title('Training and Validation Loss Curve')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        plt.grid(True)
        
        output_file = 'TrainValLoss_created.png'
        plt.savefig(output_file)
        print(f"Plot saved to: {output_file}")

    except Exception as e:
        print(f"Error creating plot: {e}")

if __name__ == "__main__":
    plot_loss_curve()