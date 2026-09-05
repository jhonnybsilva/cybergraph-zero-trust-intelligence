"""
graph_engine.py - Motor de Teoria dos Grafos & Banco Relacional SQLite
Projeto: CyberGraph AI - Inteligencia de Grafos & Deteccao de Movimentacao Lateral
Autor: Jhonny Brasiliano da Silva
"""

import networkx as nx
import pandas as pd
import numpy as np
import json
import sqlite3
import os

DB_PATH = "data/cybergraph_security.db"

def run_graph_analysis():
    print("Iniciando analise de Teoria dos Grafos (Graph Data Science)...")
    
    df_nodes = pd.read_csv("data/network_nodes.csv", keep_default_na=False)
    df_edges = pd.read_csv("data/network_edges.csv", keep_default_na=False)
    df_events = pd.read_csv("data/auth_events.csv", keep_default_na=False)
    
    if "crit" in df_nodes.columns and "criticality" not in df_nodes.columns:
        df_nodes.rename(columns={"crit": "criticality"}, inplace=True)
        df_nodes.to_csv("data/network_nodes.csv", index=False)
        
    G = nx.DiGraph()
    
    for _, row in df_nodes.iterrows():
        G.add_node(
            row["id"],
            label=row["label"],
            zone=row["zone"],
            tier=row["tier"],
            criticality=row["criticality"],
            os=row["os"]
        )
        
    for _, row in df_edges.iterrows():
        G.add_edge(
            row["source"],
            row["target"],
            type=row["type"],
            weight=row["weight"]
        )
        
    print(f"Grafo instanciado: {G.number_of_nodes()} nós e {G.number_of_edges()} arestas direcionadas.")
    
    # 1. Calculo de Métricas Centrais de Teoria dos Grafos
    print("Calculando PageRank de Privilégios e Centralidades...")
    pagerank_scores = nx.pagerank(G, weight="weight")
    betweenness_scores = nx.betweenness_centrality(G, weight="weight")
    closeness_scores = nx.closeness_centrality(G)
    in_degrees = dict(G.in_degree())
    out_degrees = dict(G.out_degree())
    
    # 2. Algoritmo de Blast Radius (Raio de Destruição)
    print("Calculando Blast Radius por ativo (Expansão de 2 saltos)...")
    blast_radius = {}
    for node in G.nodes():
        sub_nodes = set()
        for succ in G.successors(node):
            sub_nodes.add(succ)
            for succ2 in G.successors(succ):
                sub_nodes.add(succ2)
        sub_nodes.discard(node)
        
        total_crit = sum(G.nodes[n].get("criticality", 1) for n in sub_nodes)
        blast_radius[node] = {
            "compromised_node_count": len(sub_nodes),
            "blast_criticality_score": total_crit
        }
        
    # 3. Consolidação das Métricas dos Nós
    node_metrics_list = []
    for node in G.nodes():
        node_metrics_list.append({
            "node_id": node,
            "label": G.nodes[node]["label"],
            "zone": G.nodes[node]["zone"],
            "tier": G.nodes[node]["tier"],
            "criticality": G.nodes[node]["criticality"],
            "pagerank_authority": round(float(pagerank_scores[node]), 5),
            "betweenness_chokepoint": round(float(betweenness_scores[node]), 5),
            "closeness_reach": round(float(closeness_scores[node]), 5),
            "in_degree": in_degrees[node],
            "out_degree": out_degrees[node],
            "blast_radius_nodes": blast_radius[node]["compromised_node_count"],
            "blast_criticality": blast_radius[node]["blast_criticality_score"]
        })
        
    df_metrics = pd.DataFrame(node_metrics_list)
    df_metrics.to_csv("data/node_graph_metrics.csv", index=False)
    
    print("\n--- [TOP 5 PONTOS DE ESTRANGULAMENTO / CHOKEPOINTS (Betweenness)] ---")
    top_choke = df_metrics.sort_values("betweenness_chokepoint", ascending=False).head(5)
    print(top_choke[["node_id", "zone", "betweenness_chokepoint", "blast_radius_nodes"]].to_string(index=False))
    
    # 4. Estruturação do Banco de Dados Relacional SQLite
    print(f"\nCriando banco de dados relacional em {DB_PATH}...")
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE network_nodes (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        zone TEXT NOT NULL,
        tier INTEGER NOT NULL,
        criticality INTEGER NOT NULL,
        os TEXT NOT NULL
    );
    """)
    
    cursor.execute("""
    CREATE TABLE network_edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        type TEXT NOT NULL,
        weight REAL NOT NULL,
        FOREIGN KEY (source) REFERENCES network_nodes(id),
        FOREIGN KEY (target) REFERENCES network_nodes(id)
    );
    """)
    
    cursor.execute("""
    CREATE TABLE graph_metrics (
        node_id TEXT PRIMARY KEY,
        pagerank_authority REAL NOT NULL,
        betweenness_chokepoint REAL NOT NULL,
        closeness_reach REAL NOT NULL,
        in_degree INTEGER NOT NULL,
        out_degree INTEGER NOT NULL,
        blast_radius_nodes INTEGER NOT NULL,
        blast_criticality INTEGER NOT NULL,
        FOREIGN KEY (node_id) REFERENCES network_nodes(id)
    );
    """)
    
    cursor.execute("""
    CREATE TABLE auth_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        source_node TEXT NOT NULL,
        target_node TEXT NOT NULL,
        relationship TEXT NOT NULL,
        protocol TEXT NOT NULL,
        port INTEGER NOT NULL,
        source_tier INTEGER NOT NULL,
        target_tier INTEGER NOT NULL,
        privilege_delta INTEGER NOT NULL,
        bytes_transferred REAL NOT NULL,
        duration_sec REAL NOT NULL,
        failed_auth_count INTEGER NOT NULL,
        is_off_hours INTEGER NOT NULL,
        is_lateral_movement INTEGER NOT NULL,
        attack_campaign TEXT NOT NULL,
        FOREIGN KEY (source_node) REFERENCES network_nodes(id),
        FOREIGN KEY (target_node) REFERENCES network_nodes(id)
    );
    """)
    
    cursor.execute("CREATE INDEX idx_events_time ON auth_events(timestamp);")
    cursor.execute("CREATE INDEX idx_events_lateral ON auth_events(is_lateral_movement);")
    cursor.execute("CREATE INDEX idx_events_pair ON auth_events(source_node, target_node);")
    
    conn.commit()
    
    df_nodes.to_sql("network_nodes", conn, if_exists="append", index=False)
    df_edges.to_sql("network_edges", conn, if_exists="append", index=False)
    df_metrics[["node_id", "pagerank_authority", "betweenness_chokepoint", "closeness_reach", "in_degree", "out_degree", "blast_radius_nodes", "blast_criticality"]].to_sql("graph_metrics", conn, if_exists="append", index=False)
    df_events.to_sql("auth_events", conn, if_exists="append", index=False)
    
    conn.commit()
    conn.close()
    print("Banco de dados SQLite populado com sucesso!")
    
    # 5. Exportar Grafo Estruturado para o Visualizador Interativo em Canvas (graph_topology.json)
    print("Exportando topologia para o Dashboard Interativo...")
    nodes_export = []
    zone_x_centers = {
        "Endpoint_Finance": 140,
        "Endpoint_Hr": 140,
        "Endpoint_Sales": 140,
        "Endpoint_Dev": 140,
        "Endpoint_Ops": 140,
        "Endpoint_Exec": 140,
        "Edge": 380,
        "Core_Servers": 620,
        "Bastion": 620,
        "Management": 620,
        "Identity": 860,
        "Crown_Jewels": 860
    }
    
    for n in G.nodes():
        ndata = G.nodes[n]
        zone = ndata["zone"]
        base_x = zone_x_centers.get(zone, 400) + np.random.uniform(-40, 40)
        base_y = np.random.uniform(80, 520)
        
        nodes_export.append({
            "id": n,
            "label": ndata["label"],
            "zone": zone,
            "tier": ndata["tier"],
            "criticality": ndata["criticality"],
            "os": ndata["os"],
            "pagerank": round(float(pagerank_scores[n]), 4),
            "betweenness": round(float(betweenness_scores[n]), 4),
            "blast_radius": blast_radius[n]["compromised_node_count"],
            "x": round(base_x, 1),
            "y": round(base_y, 1)
        })
        
    edges_export = []
    for s, t, d in G.edges(data=True):
        edges_export.append({
            "source": s,
            "target": t,
            "type": d["type"],
            "weight": d["weight"]
        })
        
    with open("data/graph_topology.json", "w", encoding="utf-8") as f:
        json.dump({"nodes": nodes_export, "edges": edges_export}, f, indent=2)
        
    print("Topologia exportada com sucesso para data/graph_topology.json!")

if __name__ == "__main__":
    run_graph_analysis()
