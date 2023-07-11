# GDPR Checker - Encryption.py
# Patrick Thomas pwt5ca
# Created 201208
# This is provided for backwards compatability.

from PathAnalyzer import PathAnalyzer
from Preproccess import preprocess_graph

if __name__ == "__main__":
    preprocess_graph(only_encryption=True)
    pa = PathAnalyzer([])
