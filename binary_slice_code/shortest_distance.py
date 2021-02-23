#encoding=utf-8

import os
import sys
import pickle

from collections import defaultdict

def load_func_info(filepath):
    with open(filepath, 'rb') as f:
        func_info = pickle.load(f)
    return func_info


def dijsktra(graph, initial, end):
    # shortest paths is a dict of nodes
    # whose value is a tuple of (previous node, weight)
    shortest_paths = {initial: (None, 0)}
    current_node = initial
    visited = set()
    
    while current_node != end:
        visited.add(current_node)
        destinations = graph.edges[current_node]
        weight_to_current_node = shortest_paths[current_node][1]

        for next_node in destinations:
            weight = graph.weights[(current_node, next_node)] + weight_to_current_node
            if next_node not in shortest_paths:
                shortest_paths[next_node] = (current_node, weight)
            else:
                current_shortest_weight = shortest_paths[next_node][1]
                if current_shortest_weight > weight:
                    shortest_paths[next_node] = (current_node, weight)
        
        next_destinations = {node: shortest_paths[node] for node in shortest_paths if node not in visited}
        if not next_destinations:
            return "Route Not Possible"
        # next node is the destination with the lowest weight
        current_node = min(next_destinations, key=lambda k: next_destinations[k][1])
    
    # Work back through destinations in shortest path
    path = []
    while current_node is not None:
        path.append(current_node)
        next_node = shortest_paths[current_node][0]
        current_node = next_node
    # Reverse path
    path = path[::-1]
    return path

'''
class Graph():
    def __init(self):
        self.edges = defaultdict(list)
        self.weights = {}

    def add_edges(self, from_node, to_node, weight):
        #self.edges[from_node].append(to_node)
        self.edges[from_node].append(to_node)
        self.weights[(from_node, to_node)] = weight
'''

class Graph():
    def __init__(self):
        """
        self.edges is a dict of all possible next nodes
        e.g. {'X': ['A', 'B', 'C', 'E'], ...}
        self.weights has all the weights between two nodes,
        with the two nodes as a tuple as the key
        e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
        """
        self.edges = defaultdict(list)
        self.weights = {}

    def add_edge(self, from_node, to_node, weight):
        # Note: assumes edges are bi-directional
        self.edges[from_node].append(to_node)
        #self.edges[to_node].append(from_node)
        self.weights[(from_node, to_node)] = weight
        #self.weights[(to_node, from_node)] = weight

def get_edges(func_info):
    edges = []
    instr_blk_map = {}

    for bb in func_info.bbs:
        #print ('start_address of blk', bb.start_address)
        #print ('preds', bb.preds)
        #print ('succs', bb.succs)
        
        for pred in bb.preds:
            edges.append((pred.replace('L',''), bb.start_address.replace('L',''), 1))
        for succ in bb.succs:
            edges.append((bb.start_address.replace('L',''), succ.replace('L',''), 1))

        for instr in bb.binstrs:
            #print ('start_address of instr', instr.start_address)
            instr_blk_map[str(hex(instr.start_address))] = bb.start_address.replace('L','')

    return edges, instr_blk_map


def construct_graph(func_info):
    graph = Graph()
    edges, instr_blk_map = get_edges(func_info)
    #print ('edges', edges)

    for edge in edges:
        graph.add_edge(*edge)

    return graph, instr_blk_map 

def main(func_info_path):
    func_info = load_func_info(func_info_path)
    graph, instr_blk_map = construct_graph(func_info)
    #print (instr_blk_map)


    res = dijsktra(graph, instr_blk_map['0xc1a6f'], instr_blk_map['0xc1e8a'])
    print ('length', len(res)-1)
    print (res)


if __name__ == '__main__':
    func_info_path = sys.argv[1]
    main(func_info_path)
