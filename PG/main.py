import tkinter as tk
from gui.app import PasswordGeneratorApp
import sys
import os

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
    sys.path.append(
        os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__))))