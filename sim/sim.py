#!/usr/bin/env python3
"""
Meta Attack Language Attack Graph Simulator
Main executable entry point

Usage: sim [attackgraph.yml path] [entry point count] [entry points...] [target] [iterations] [options]

Examples:
  sim graph.yml 1 EntryPoint Target 1000
  sim graph.yml 2 EP1 EP2 Target 5000 -h
  sim graph.yml 1 Entry Target 1000 -a -h
"""

def main():
    """Main entry point for sim command"""
    from cli import main as cli_main
    cli_main()

if __name__ == "__main__":
    main()