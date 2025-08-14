#!/usr/bin/env python3
"""
Setup script for Meta Attack Language Attack Graph Simulator
"""

import os
from setuptools import setup

# Read README if exists, otherwise use default description
try:
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = "Meta Attack Language Attack Graph Simulator with Enhanced Features"

# Read requirements if exists, otherwise use default
try:
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
except FileNotFoundError:
    requirements = [
        "numpy>=1.20.0",
        "matplotlib>=3.3.0",
        "graphviz>=0.16",
        "PyYAML>=5.4.0"
    ]

setup(
    name="mal-attack-graph-simulator",
    version="2.0.0",
    author="Attack Graph Simulator Team",
    description="Meta Attack Language Attack Graph Simulator with Enhanced Features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    py_modules=[
        "sim",
        "cli", 
        "simulator_core",
        "attack_step",
        "visualizer",
        "utils"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sim=sim:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)