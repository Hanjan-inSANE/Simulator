# Meta Attack Language Attack Graph Simulator

Enhanced attack graph simulator with random tie-breaking and fixed hidden node processing.

## Features

- 🎯 **Accurate Simulation**: Event-driven simulation with proper AND/OR node logic
- 🎲 **Random Tie-Breaking**: Eliminates deterministic bias in path selection
- 👁️ **Hidden Node Support**: Correctly handles hidden nodes in visualization
- 📊 **Rich Visualization**: Generates critical paths, all paths, and TTC distributions
- ⚡ **High Performance**: Optimized for large attack graphs and many iterations
- 🛠️ **Easy to Use**: Simple command-line interface

## Installation

### Option 1: Direct Installation
```bash
pip install -r requirements.txt
```

### Option 2: Development Installation
```bash
pip install -e .
```

### Option 3: Manual Setup
```bash
# Install dependencies
pip install numpy matplotlib graphviz PyYAML

# Make sim.py executable
chmod +x sim.py
```

## Usage

### Basic Usage
```bash
sim [attackgraph.yml] [entry_count] [entry_points...] [target] [iterations]
```

### Examples

**Single Entry Point:**
```bash
sim graph.yml 1 EntryPoint Target 1000
```

**Multiple Entry Points:**
```bash
sim graph.yml 2 EP1 EP2 Target 5000
```

**With Options:**
```bash
# Hide hidden nodes and generate all paths
sim graph.yml 1 Entry Target 1000 -h -a
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h, --hide-hidden` | Hide nodes with 'hidden' tag | Show all nodes |
| `-a, --allpaths` | Generate allpaths.png | Only critical_paths.png |
| `--help` | Show help message | - |
| `--version` | Show version info | - |

## Output Files

The simulator generates the following visualization files:

### 📈 critical_paths.png (Always Generate