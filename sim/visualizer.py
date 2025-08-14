#!/usr/bin/env python3
"""
Visualization module for Meta Attack Language Attack Graph Simulator
"""

import graphviz
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from attack_step import AttackStep


class AttackGraphVisualizer:
    """Attack graph visualization handler"""
    
    def __init__(self, simulator):
        self.simulator = simulator
        
    def generate_allpaths(self, hide_hidden: bool = False):
        """Generate allpaths.png"""
        print("  Generating allpaths.png")
        
        graph = graphviz.Digraph(format='png')
        graph.attr(rankdir='TB')
        graph.attr('node', shape='box', style='rounded,filled')
        
        # Determine visible nodes
        if hide_hidden:
            visible_nodes = {nid for nid in self.simulator.path_nodes 
                           if not self.simulator.is_hidden_for_visualization(nid)}
        else:
            visible_nodes = self.simulator.path_nodes.copy()
        
        # Add visible nodes
        for node_id in visible_nodes:
            step = self.simulator.attack_steps[node_id]
            label = self._format_label(step)
            color = self._get_color(step, node_id)
            graph.node(str(node_id), label=label, fillcolor=color)
        
        # Add edges
        if hide_hidden:
            self._add_edges_skip_hidden(graph, visible_nodes)
        else:
            for src, tgt in self.simulator.path_edges:
                if src in visible_nodes and tgt in visible_nodes:
                    graph.edge(str(src), str(tgt))
        
        # Add defense and exist connections (for allpaths, show all)
        self._add_special_connections_allpaths(graph, visible_nodes, hide_hidden)
        
        try:
            graph.render('allpaths', cleanup=True)
            print("  Generated allpaths.png")
        except Exception as e:
            print(f"  Error generating allpaths.png: {e}")

    def generate_critical_paths(self, edge_counts, hide_hidden: bool = False):
        """Generate critical_paths.png"""
        print("  Generating critical_paths.png")
        
        graph = graphviz.Digraph(format='png')
        graph.attr(rankdir='TB')
        graph.attr('node', shape='box', style='rounded,filled')
        
        # Get nodes from simulation results
        nodes_in_results = {nid for edge in edge_counts for nid in edge}
        nodes_in_results.update([self.simulator.target])
        nodes_in_results.update(self.simulator.entry_points)
        
        # Filter visible nodes if hiding hidden
        if hide_hidden:
            visible_nodes = {nid for nid in nodes_in_results 
                           if nid in self.simulator.attack_steps and not self.simulator.is_hidden_for_visualization(nid)}
        else:
            visible_nodes = nodes_in_results.copy()
        
        # Add visible nodes
        for node_id in visible_nodes:
            if node_id in self.simulator.attack_steps:
                step = self.simulator.attack_steps[node_id]
                label = self._format_label(step)
                color = self._get_color(step, node_id)
                graph.node(str(node_id), label=label, fillcolor=color)
        
        # Add critical edges with frequency-based styling
        if edge_counts:
            if hide_hidden:
                self._add_critical_edges_path_based(graph, edge_counts, visible_nodes)
            else:
                # Direct edges when not hiding
                max_count = max(edge_counts.values())
                for (src, tgt), count in edge_counts.items():
                    if src in visible_nodes and tgt in visible_nodes:
                        frequency = count / max_count
                        if frequency >= 0.7:
                            color, width = 'red', '3'
                        elif frequency >= 0.4:
                            color, width = 'orange', '2'
                        else:
                            color, width = 'yellow', '1'
                        graph.edge(str(src), str(tgt), color=color, penwidth=width)
        
        # Add defense and exist connections (for critical paths, filter inactive ones)
        self._add_special_connections_critical_paths(graph, visible_nodes, hide_hidden)
        
        try:
            graph.render('critical_paths', cleanup=True)
            print("  Generated critical_paths.png")
        except Exception as e:
            print(f"  Error generating critical_paths.png: {e}")

    def generate_ttc_distribution(self, global_ttcs: List[float]):
        """Generate global_ttc.png"""
        print("  Generating global_ttc.png")
        
        if not global_ttcs:
            return
        
        sorted_ttcs = np.sort(global_ttcs)
        n = len(sorted_ttcs)
        cumulative_probs = np.arange(1, n + 1) / n * 100
        
        plt.figure(figsize=(10, 6))
        plt.plot(sorted_ttcs, cumulative_probs, 'b-', linewidth=2)
        plt.xlabel('Global TTC')
        plt.ylabel('Cumulative Probability (%)')
        plt.title('Cumulative Distribution of Global TTC')
        plt.grid(True, alpha=0.3)
        plt.xlim(0, sorted_ttcs[-1] * 1.1)
        plt.ylim(0, 100)
        
        plt.tight_layout()
        plt.savefig('global_ttc.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("  Generated global_ttc.png")

    def _add_edges_skip_hidden(self, graph, visible_nodes):
        """Skip hidden nodes and connect visible nodes directly"""
        def find_visible_descendants(node_id, visited=None):
            """Find all visible descendants, skipping hidden nodes"""
            if visited is None:
                visited = set()
            if node_id in visited or node_id not in self.simulator.attack_steps:
                return set()
            
            visited.add(node_id)
            descendants = set()
            step = self.simulator.attack_steps[node_id]
            
            for child_id in step.children:
                if child_id not in self.simulator.path_nodes:
                    continue
                    
                if child_id in self.simulator.attack_steps:
                    # If child is visible, add it directly
                    if not self.simulator.is_hidden_for_visualization(child_id) and child_id in visible_nodes:
                        descendants.add(child_id)
                    # If child is hidden, recursively find its visible descendants
                    elif self.simulator.is_hidden_for_visualization(child_id):
                        child_descendants = find_visible_descendants(child_id, visited.copy())
                        descendants.update(child_descendants)
            
            return descendants
        
        # For each visible node, find its visible descendants and connect directly
        # CRITICAL: Skip target - target should have NO outgoing edges
        for node_id in visible_nodes:
            if node_id == self.simulator.target:
                continue  # Skip target completely
                
            visible_descendants = find_visible_descendants(node_id)
            for desc_id in visible_descendants:
                if desc_id in visible_nodes and desc_id != node_id and desc_id not in self.simulator.entry_points:  # Avoid self-loops
                    graph.edge(str(node_id), str(desc_id))

    def _add_critical_edges_path_based(self, graph, edge_counts, visible_nodes):
        """Add critical edges while maintaining correct adjacency using path-based processing"""
        # Build adjacency graph from simulation edges
        adjacency = defaultdict(set)
        for (src, tgt), count in edge_counts.items():
            adjacency[src].add(tgt)
        
        # Function to find ONLY the immediate next visible node
        def find_immediate_visible_successor(start_node, visited=None):
            """Find ONLY the immediate next visible node, stopping at first visible found"""
            if visited is None:
                visited = set()
            if start_node in visited or start_node not in self.simulator.attack_steps:
                return None
            
            visited.add(start_node)
            
            # Check all direct successors
            for next_node in adjacency.get(start_node, set()):
                if next_node in self.simulator.attack_steps and next_node not in visited:
                    # If next node is visible, return it immediately
                    if not self.simulator.is_hidden_for_visualization(next_node) and next_node in visible_nodes:
                        return next_node
                    
                    # If next node is hidden, recursively find its immediate visible successor
                    elif self.simulator.is_hidden_for_visualization(next_node):
                        result = find_immediate_visible_successor(next_node, visited.copy())
                        if result:
                            return result  # Return first visible found, stop searching
            
            return None
        
        # Build visible edges from simulation paths
        visible_edge_counts = defaultdict(int)
        
        # Process each simulation edge to create proper visible connections
        for (src, tgt), count in edge_counts.items():
            # Determine visible source
            if src in visible_nodes and not self.simulator.is_hidden_for_visualization(src):
                vis_src = src
            else:
                # Find the visible predecessor of this hidden source
                vis_src = self._find_visible_predecessor(src, edge_counts, visible_nodes)
            
            # Determine visible target
            if tgt in visible_nodes and not self.simulator.is_hidden_for_visualization(tgt):
                vis_tgt = tgt
            else:
                # Find the immediate visible successor of this hidden target
                vis_tgt = find_immediate_visible_successor(tgt)
            
            # Only create edge if we have valid visible endpoints and they're different
            if (vis_src and vis_tgt and vis_src != vis_tgt and 
                vis_src in visible_nodes and vis_tgt in visible_nodes):
                # Check if this creates a valid adjacent connection
                if self._is_valid_adjacent_connection(vis_src, vis_tgt, adjacency):
                    visible_edge_counts[(vis_src, vis_tgt)] = max(
                        visible_edge_counts[(vis_src, vis_tgt)], count
                    )
        
        # Add edges with frequency-based styling
        if visible_edge_counts:
            max_count = max(visible_edge_counts.values())
            for (src, tgt), count in visible_edge_counts.items():
                frequency = count / max_count
                if frequency >= 0.7:
                    color, width = 'red', '3'
                elif frequency >= 0.4:
                    color, width = 'orange', '2'
                else:
                    color, width = 'yellow', '1'
                graph.edge(str(src), str(tgt), color=color, penwidth=width)

    def _find_visible_predecessor(self, hidden_node, edge_counts, visible_nodes):
        """Find the visible predecessor of a hidden node"""
        # Look for edges that end at this hidden node
        for (src, tgt), count in edge_counts.items():
            if tgt == hidden_node:
                if src in visible_nodes and not self.simulator.is_hidden_for_visualization(src):
                    return src
                else:
                    # Recursively find visible predecessor
                    return self._find_visible_predecessor(src, edge_counts, visible_nodes)
        return None

    def _is_valid_adjacent_connection(self, vis_src, vis_tgt, adjacency):
        """Check if connection between vis_src and vis_tgt represents valid adjacency"""
        def path_exists(start, end, visited=None):
            """Check if there's a path from start to end through the adjacency graph"""
            if visited is None:
                visited = set()
            if start in visited:
                return False
            if start == end:
                return True
            
            visited.add(start)
            
            # Check direct connection first
            if end in adjacency.get(start, set()):
                return True
            
            # Check through hidden nodes only (don't skip multiple visible nodes)
            for next_node in adjacency.get(start, set()):
                if next_node in self.simulator.attack_steps:
                    # If next node is visible and not the target, stop (no skipping visible nodes)
                    if (not self.simulator.is_hidden_for_visualization(next_node) and 
                        next_node != end):
                        continue
                    
                    # If hidden or is the target, continue searching
                    if path_exists(next_node, end, visited.copy()):
                        return True
            
            return False
        
        return path_exists(vis_src, vis_tgt)

    def _add_special_connections_allpaths(self, graph, visible_nodes, hide_hidden):
        """Add defense and exist connections for allpaths (show all)"""
        # Add defense nodes and connections
        for def_id, def_step in self.simulator.defense_nodes.items():
            show_defense = not hide_hidden or not self.simulator.is_hidden_for_visualization(def_id)
            
            if show_defense:
                affected_nodes = self._find_affected_visible_nodes(def_step, visible_nodes, hide_hidden)
                
                if affected_nodes:
                    label = self._format_label(def_step)
                    graph.node(str(def_id), label=label, fillcolor='lightblue', shape='diamond')
                    
                    for affected_id, is_hidden_target in affected_nodes:
                        # Blue solid line for direct, dashed for hidden targets
                        style = 'dashed' if is_hidden_target else 'solid'
                        graph.edge(str(def_id), str(affected_id), color='blue', style=style)
        
        # Add exist nodes and connections
        for exist_id, exist_step in self.simulator.exist_nodes.items():
            show_exist = not hide_hidden or not self.simulator.is_hidden_for_visualization(exist_id)
            
            if show_exist:
                affected_nodes = self._find_affected_visible_nodes(exist_step, visible_nodes, hide_hidden)
                
                if affected_nodes:
                    label = self._format_label(exist_step)
                    graph.node(str(exist_id), label=label, fillcolor='lightgray', shape='hexagon')
                    
                    for affected_id, is_hidden_target in affected_nodes:
                        graph.edge(str(exist_id), str(affected_id), color='purple', style='dotted')

    def _add_special_connections_critical_paths(self, graph, visible_nodes, hide_hidden):
        """Add defense and exist connections for critical_paths (filter inactive ones)"""
        # Add defense nodes and connections (only if defense_status > 0.0)
        for def_id, def_step in self.simulator.defense_nodes.items():
            # Filter: only show if defense_status > 0.0
            if def_step.defend_success <= 0.0:
                continue
                
            show_defense = not hide_hidden or not self.simulator.is_hidden_for_visualization(def_id)
            
            if show_defense:
                affected_nodes = self._find_affected_visible_nodes(def_step, visible_nodes, hide_hidden)
                
                if affected_nodes:
                    label = self._format_label(def_step)
                    graph.node(str(def_id), label=label, fillcolor='lightblue', shape='diamond')
                    
                    for affected_id, is_hidden_target in affected_nodes:
                        # Blue solid line for direct, dashed for hidden targets
                        style = 'dashed' if is_hidden_target else 'solid'
                        graph.edge(str(def_id), str(affected_id), color='blue', style=style)
        
        # Add exist nodes and connections (only if existence_status is True)
        for exist_id, exist_step in self.simulator.exist_nodes.items():
            # Filter: only show if existence_status is True
            if not exist_step.defend_success:  # defend_success stores the boolean value
                continue
                
            show_exist = not hide_hidden or not self.simulator.is_hidden_for_visualization(exist_id)
            
            if show_exist:
                affected_nodes = self._find_affected_visible_nodes(exist_step, visible_nodes, hide_hidden)
                
                if affected_nodes:
                    label = self._format_label(exist_step)
                    graph.node(str(exist_id), label=label, fillcolor='lightgray', shape='hexagon')
                    
                    for affected_id, is_hidden_target in affected_nodes:
                        graph.edge(str(exist_id), str(affected_id), color='purple', style='dotted')

    def _find_affected_visible_nodes(self, special_step, visible_nodes, hide_hidden):
        """Find which visible nodes are affected by defense/exist, handling hidden nodes"""
        affected = []
        
        def find_visible_descendants_recursive(node_id, is_hidden_path=False, visited=None):
            if visited is None:
                visited = set()
            if node_id in visited or node_id not in self.simulator.attack_steps:
                return []
            
            visited.add(node_id)
            descendants = []
            step = self.simulator.attack_steps[node_id]
            
            for child_id in step.children:
                if child_id not in self.simulator.path_nodes:
                    continue
                    
                if child_id in self.simulator.attack_steps:
                    if hide_hidden:
                        if not self.simulator.is_hidden_for_visualization(child_id) and child_id in visible_nodes:
                            descendants.append((child_id, is_hidden_path))
                        elif self.simulator.is_hidden_for_visualization(child_id):
                            descendants.extend(find_visible_descendants_recursive(child_id, True, visited.copy()))
                    else:
                        if child_id in visible_nodes:
                            descendants.append((child_id, False))
            
            return descendants
        
        # Find affected visible nodes for this special step
        for child_id in special_step.children:
            if child_id not in self.simulator.path_nodes:
                continue
                
            if child_id in self.simulator.attack_steps:
                if hide_hidden:
                    if not self.simulator.is_hidden_for_visualization(child_id) and child_id in visible_nodes:
                        # Direct connection to visible node
                        affected.append((child_id, False))
                    elif self.simulator.is_hidden_for_visualization(child_id):
                        # Connection through hidden node - find visible descendants
                        affected.extend(find_visible_descendants_recursive(child_id, True))
                else:
                    if child_id in visible_nodes:
                        # Direct connection when not hiding
                        affected.append((child_id, False))
        
        return affected

    def _format_label(self, step: AttackStep) -> str:
        """Format node label"""
        name_parts = step.name.split(':')
        if len(name_parts) >= 3:
            label = f"{name_parts[0]}:{name_parts[1]}\\n{name_parts[2]}"
        else:
            label = step.name.replace(':', '\\n')
        
        # Add TTC info
        if step.ttc_dist and step.ttc_dist.get('name'):
            func_name = step.ttc_dist['name']
            args = step.ttc_dist.get('arguments', [])
            
            # Check if it's a predefined combination distribution (no arguments)
            predefined_distributions = {
                'EasyAndCertain', 'EasyAndUncertain', 'HardAndCertain', 
                'HardAndUncertain', 'VeryHardAndCertain', 'VeryHardAndUncertain'
            }
            
            if func_name in predefined_distributions:
                # For predefined distributions, just show the name without arguments
                label += f"\\n[{func_name}]"
            elif args:
                # For basic distributions with arguments, show function name and args
                args_str = ', '.join(f"{arg:.2f}" if isinstance(arg, float) else str(arg) 
                                   for arg in args[:2])  # Only show first 2 args
                label += f"\\n[{func_name}({args_str})]"
            else:
                # For distributions without arguments
                label += f"\\n[{func_name}()]"
        
        # Add defense info
        if step.defended_by:
            label += f"\\n[Defended: {step.defend_success:.2f}]"
        
        # Add status info for special nodes
        if step.type == 'defense':
            label += f"\\ndefense_status:{step.defend_success:.2f}"
        elif step.type in {'exist', 'notExist', 'notExists'}:
            label += f"\\nexistence_status:{step.defend_success}"
        
        return label

    def _get_color(self, step: AttackStep, node_id: int) -> str:
        """Get node color"""
        if node_id in self.simulator.entry_points:
            return 'lightgreen'
        elif node_id == self.simulator.target:
            return 'red'
        elif step.type == 'defense':
            return 'lightblue'
        elif step.type == 'and':
            return 'lightyellow'
        elif step.type == 'or':
            return 'white'
        elif step.type in {'exist', 'notExist', 'notExists'}:
            return 'lightgray'
        else:
            return 'lightcyan'