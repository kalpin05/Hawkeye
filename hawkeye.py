import sys
import os

# Fix for Windows path resolution
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from cli.main import hawkeye

if __name__ == "__main__":
    hawkeye()