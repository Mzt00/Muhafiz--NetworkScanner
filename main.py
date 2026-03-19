import sys
import os
import logging
 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
 
from core import run_scan
 
if __name__ == "__main__":
    result = run_scan()
 