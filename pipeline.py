"""
pipeline.py - Pipeline de Machine Learning para Detecção de Movimentação Lateral
Projeto: CyberGraph AI - Inteligencia de Grafos & Deteccao de Movimentacao Lateral
Autor: Jhonny Brasiliano da Silva
"""

import sqlite3
import pandas as pd
import numpy as np
import json
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report, roc_auc_score, average_precision_score,
    confusion_matrix, f1_score, precision_score, recall_score
)

def run_ml_pipeline():
    print("Iniciando Pipeline de Machine Learning & Graph Feature Engineering...")
    
    conn = sqlite3.connect("data/cybergraph_security.db")
    
    query = """
    SELECT 
        e.*,
        m_src.pagerank_authority AS src_pagerank,
        m_src.betweenness_chokepoint AS src_betweenness,
        m_src.blast_radius_nodes AS src_blast_nodes,
        m_src.blast_criticality AS src_blast_crit,
        m_dst.pagerank_authority AS dst_pagerank,
        m_dst.betweenness_chokepoint AS dst_betweenness,
        m_dst.blast_radius_nodes AS dst_blast_nodes,
        m_dst.blast_criticality AS dst_blast_crit
    FROM auth_events e
    JOIN graph_metrics m_src ON e.source_node = m_src.node_id
    JOIN graph_metrics m_dst ON e.target_node = m_dst.node_id
    ORDER BY e.timestamp ASC;
    """
    
    df = pd.read_sql(query, conn)
    conn.close()
    
    print(f"Total de eventos enriquecidos com Métricas de Grafos: {len(df):,}")
    
    # Feature Engineering de Grafos + Telemetria
    print("Criando variáveis de interação topológica e risco Zero-Trust...")
    df['privilege_risk_ratio'] = df['privilege_delta'] * (df['dst_betweenness'] + 0.01)
    df['blast_gradient'] = df['dst_blast_crit'] - df['src_blast_crit']
    df['exfil_rate'] = df['bytes_transferred'] / (df['duration_sec'] + 0.1)
    df['pagerank_jump'] = df['dst_pagerank'] - df['src_pagerank']
    df['off_hours_failed_auth'] = df['is_off_hours'] * df['failed_auth_count']
    
    features = [
        'source_tier', 'target_tier', 'privilege_delta', 'bytes_transferred',
        'duration_sec', 'failed_auth_count', 'is_off_hours',
        'src_pagerank', 'src_betweenness', 'src_blast_nodes',
        'dst_pagerank', 'dst_betweenness', 'dst_blast_nodes',
        'privilege_risk_ratio', 'blast_gradient', 'exfil_rate',
        'pagerank_jump', 'off_hours_failed_auth'
    ]
    
    X = df[features]
    y = df['is_lateral_movement']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    # 1. Modelo Supervisionado: Detecção de Movimentação Lateral
    print("\n--- Treinando Modelo 1: HistGradientBoosting Classifier (Zero-Trust Interceptor) ---")
    clf = HistGradientBoostingClassifier(
        max_iter=160,
        learning_rate=0.07,
        max_leaf_nodes=31,
        random_state=42
    )
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    roc = roc_auc_score(y_test, y_prob)
    pr_auc = average_precision_score(y_test, y_prob)
    f1 = f1_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print(f"ROC-AUC Score: {roc:.4f}")
    print(f"PR-AUC Score:  {pr_auc:.4f}")
    print(f"F1-Score:      {f1:.4f}")
    print(f"Precisão:      {prec:.4f} | Recall: {rec:.4f}")
    print("Matriz de Confusão:")
    print(cm)
    
    # Importância dos Atributos
    print("\nCalculando Pesos e Importância dos Atributos Topológicos...")
    rf = RandomForestClassifier(n_estimators=60, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    feat_importances = [
        {"feature": col, "importance": round(float(imp), 4)}
        for col, imp in sorted(zip(features, rf.feature_importances_), key=lambda x: x[1], reverse=True)
    ]
    for item in feat_importances[:8]:
        print(f"  {item['feature']:<25}: {item['importance']:.4f}")

    # 2. Modelo Não-Supervisionado (Isolation Forest)
    print("\n--- Treinando Modelo 2: Detecção Não-Supervisionada de Anomalias Estruturais ---")
    iso = IsolationForest(contamination=0.03, random_state=42, n_jobs=-1)
    iso.fit(X_train)
    iso_preds = np.where(iso.predict(X_test) == -1, 1, 0)
    iso_f1 = f1_score(y_test, iso_preds)
    print(f"Isolation Forest F1-Score contra Ataques Reais: {iso_f1:.4f}")
    
    # Salvar modelos
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, "models/lateral_movement_detector.joblib")
    joblib.dump(iso, "models/graph_anomaly_isolation.joblib")
    
    metrics = {
        "total_nodes": 46,
        "total_edges": 120,
        "total_events": len(df),
        "lateral_movement_rate_pct": round(float(y.mean() * 100), 2),
        "supervised_model": {
            "name": "HistGradientBoosting Classifier (Zero-Trust Interceptor)",
            "roc_auc": round(float(roc), 4),
            "pr_auc": round(float(pr_auc), 4),
            "f1_score": round(float(f1), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "confusion_matrix": {
                "true_negative": int(cm[0][0]),
                "false_positive": int(cm[0][1]),
                "false_negative": int(cm[1][0]),
                "true_positive": int(cm[1][1])
            }
        },
        "unsupervised_model": {
            "name": "Isolation Forest (Zero-Day Anomaly Detection)",
            "contamination": 0.03,
            "f1_score": round(float(iso_f1), 4)
        },
        "feature_importances": feat_importances
    }
    
    with open("models/metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        
    print("Pipeline de Machine Learning concluído com êxito!")

if __name__ == "__main__":
    run_ml_pipeline()
