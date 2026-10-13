"""Setup script for Multi-Agent PQC-IDS."""

from setuptools import setup, find_packages

setup(
    name="multi-agent-pqc-ids",
    version="1.0.0",
    description="Multi-Agent PQC-IDS: Post-Quantum Cryptography-Aware Intrusion Detection System",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Roger Nick Anaedevha",
    author_email="roger@robustidps.ai",
    url="https://github.com/rogerpanel/Multi-Agent-PQC-models",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "torch>=2.0.0",
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scikit-learn>=1.3.0",
        "pyyaml>=6.0",
        "matplotlib>=3.7.0",
        "tqdm>=4.65.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
    keywords="intrusion-detection post-quantum-cryptography multi-agent deep-learning",
)
