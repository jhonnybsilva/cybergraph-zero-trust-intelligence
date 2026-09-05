"""
generator.py - Gerador de Topologia de Rede Zero-Trust e Telemetria de Grafos
Projeto: CyberGraph AI - Inteligencia de Grafos & Deteccao de Movimentacao Lateral
Autor: Jhonny Brasiliano da Silva
"""

import numpy as np
import pandas as pd
import json
import random
from datetime import datetime, timedelta
import os

np.random.seed(42)
random.seed(42)

def generate_cybergraph_data():
    print("Iniciando construcao da Topologia de Rede Corporativa (Graph Generation)...")
    
    # 1. Definicao dos Nos da Rede
    nodes = []
    
    # Tier 0 - Crown Jewels & Controladores de Dominio (Privilegio Maximo)
    t0_nodes = [
        {"id": "dc-corp-primary", "label": "Primary Domain Controller (AD)", "zone": "Identity", "tier": 0, "crit": 10, "os": "Windows Server 2022"},
        {"id": "dc-corp-backup", "label": "Backup Domain Controller", "zone": "Identity", "tier": 0, "crit": 10, "os": "Windows Server 2022"},
        {"id": "db-prod-erp", "label": "ERP Production Database (Oracle/SAP)", "zone": "Crown_Jewels", "tier": 0, "crit": 10, "os": "RHEL 9"},
        {"id": "db-cust-sql", "label": "Customer PII Database (Postgres)", "zone": "Crown_Jewels", "tier": 0, "crit": 10, "os": "RHEL 9"},
        {"id": "cloud-kms-vault", "label": "Cloud Key Management Vault", "zone": "Crown_Jewels", "tier": 0, "crit": 9, "os": "Linux Hardened"},
        {"id": "swift-pay-gateway", "label": "Financial Payment Core Gateway", "zone": "Crown_Jewels", "tier": 0, "crit": 10, "os": "AIX Secure"}
    ]
    nodes.extend(t0_nodes)
    
    # Tier 1 - Servidores de Gestao, Bastions e Nucleo
    t1_nodes = [
        {"id": "bastion-rdp-01", "label": "Jump Server Bastion RDP", "zone": "Bastion", "tier": 1, "crit": 8, "os": "Windows Server 2022"},
        {"id": "bastion-ssh-01", "label": "Jump Host SSH Linux", "zone": "Bastion", "tier": 1, "crit": 8, "os": "Ubuntu Server"},
        {"id": "entra-id-sync", "label": "Entra ID / M365 Cloud Sync", "zone": "Identity", "tier": 1, "crit": 8, "os": "Windows Server 2022"},
        {"id": "sec-siem-collector", "label": "SIEM Log Collector", "zone": "Management", "tier": 1, "crit": 7, "os": "Debian Linux"},
        {"id": "bkp-nas-core", "label": "Immutable Backup NAS Appliance", "zone": "Management", "tier": 1, "crit": 8, "os": "TrueNAS Enterprise"},
        {"id": "app-api-gateway", "label": "Core Internal API Gateway", "zone": "Core_Servers", "tier": 1, "crit": 7, "os": "Alpine Linux"},
        {"id": "srv-git-enterprise", "label": "Enterprise Code Repository", "zone": "Core_Servers", "tier": 1, "crit": 7, "os": "Ubuntu Server"},
        {"id": "srv-file-smb", "label": "Corporate File Sharing (SMB)", "zone": "Core_Servers", "tier": 1, "crit": 6, "os": "Windows Server 2022"}
    ]
    nodes.extend(t1_nodes)
    
    # Tier 2 - Perimetro, Borda e DMZ
    t2_nodes = [
        {"id": "edge-vpn-gw", "label": "Global Remote Access VPN Gateway", "zone": "Edge", "tier": 2, "crit": 6, "os": "Cisco ASA / Firepower"},
        {"id": "edge-dmz-proxy", "label": "Reverse Web Proxy DMZ", "zone": "Edge", "tier": 2, "crit": 5, "os": "Nginx Hardened"},
        {"id": "firewall-internal", "label": "Internal Core Segmentation Firewall", "zone": "Edge", "tier": 2, "crit": 7, "os": "Fortinet FortiGate"},
        {"id": "waf-edge-cloud", "label": "Cloud Edge WAF & DDoS Shield", "zone": "Edge", "tier": 2, "crit": 6, "os": "Cloudflare Enterprise"}
    ]
    nodes.extend(t2_nodes)
    
    # Tier 3 - Endpoints / Estacoes de Trabalho
    depts = ["finance", "hr", "dev", "sales", "ops", "exec"]
    for dept in depts:
        count = 6 if dept in ["finance", "dev"] else 4
        for i in range(1, count + 1):
            crit = 4 if dept in ["finance", "exec"] else (3 if dept == "dev" else 2)
            nodes.append({
                "id": f"ws-{dept}-{i:02d}",
                "label": f"Workstation {dept.capitalize()} {i:02d}",
                "zone": f"Endpoint_{dept.capitalize()}",
                "tier": 3,
                "crit": crit,
                "os": "Windows 11 Enterprise" if i % 2 == 0 else "macOS Sonoma"
            })
            
    df_nodes = pd.DataFrame(nodes)
    print(f"Total de Nos (Assets) criados no grafo: {len(df_nodes)}")
    
    # 2. Definicao de Arestas da Topologia (Trust Relationships e Redes)
    edges = []
    
    # Endpoints acessam arquivos, proxys e VPN
    for n in nodes:
        nid = n["id"]
        if n["tier"] == 3: # Estacoes
            edges.append({"source": nid, "target": "srv-file-smb", "type": "SMB_SHARE_MOUNT", "weight": 2.0})
            edges.append({"source": nid, "target": "edge-dmz-proxy", "type": "HTTP_PROXY", "weight": 1.0})
            
            # Devs tem acesso ao Git e Bastion SSH
            if "dev" in nid:
                edges.append({"source": nid, "target": "srv-git-enterprise", "type": "GIT_SSH_ACCESS", "weight": 1.5})
                edges.append({"source": nid, "target": "bastion-ssh-01", "type": "CAN_SSH_TO", "weight": 3.0})
            # Financeiros tem acesso RDP ao ERP
            if "finance" in nid or "exec" in nid:
                edges.append({"source": nid, "target": "bastion-rdp-01", "type": "CAN_RDP_TO", "weight": 2.5})
            # Ops tem acesso ao SIEM
            if "ops" in nid:
                edges.append({"source": nid, "target": "bastion-ssh-01", "type": "CAN_SSH_TO", "weight": 2.0})
                edges.append({"source": nid, "target": "sec-siem-collector", "type": "HTTPS_MGMT", "weight": 1.5})
                
    # Bastions tem acesso aos Servidores Centrais e DBs
    edges.append({"source": "bastion-rdp-01", "target": "dc-corp-primary", "type": "ADMINS_ON", "weight": 1.0})
    edges.append({"source": "bastion-rdp-01", "target": "dc-corp-backup", "type": "ADMINS_ON", "weight": 1.0})
    edges.append({"source": "bastion-rdp-01", "target": "db-prod-erp", "type": "DB_ADMIN_CONSOLE", "weight": 1.2})
    edges.append({"source": "bastion-ssh-01", "target": "db-cust-sql", "type": "SSH_TUNNEL", "weight": 1.2})
    edges.append({"source": "bastion-ssh-01", "target": "cloud-kms-vault", "type": "SSH_KEY_AUTH", "weight": 1.5})
    edges.append({"source": "bastion-rdp-01", "target": "swift-pay-gateway", "type": "PRIVILEGED_RDP", "weight": 1.0})
    
    # Relacionamentos de Dominio e Identidade
    edges.append({"source": "dc-corp-primary", "target": "dc-corp-backup", "type": "AD_REPLICATION", "weight": 0.5})
    edges.append({"source": "entra-id-sync", "target": "dc-corp-primary", "type": "LDAP_SYNC", "weight": 0.8})
    edges.append({"source": "app-api-gateway", "target": "db-cust-sql", "type": "SQL_QUERY_CLIENT", "weight": 1.0})
    edges.append({"source": "app-api-gateway", "target": "db-prod-erp", "type": "SQL_QUERY_CLIENT", "weight": 1.0})
    edges.append({"source": "edge-vpn-gw", "target": "firewall-internal", "type": "TRAFFIC_ROUTED", "weight": 1.0})
    edges.append({"source": "firewall-internal", "target": "bastion-rdp-01", "type": "TRAFFIC_FILTERED", "weight": 1.5})
    
    # Interconexoes entre estacoes da mesma subrede (possivel movimentacao lateral peer-to-peer)
    for dept in depts:
        dnodes = [n["id"] for n in nodes if f"ws-{dept}" in n["id"]]
        for idx in range(len(dnodes) - 1):
            edges.append({
                "source": dnodes[idx],
                "target": dnodes[idx+1],
                "type": "LAN_PEER_CONNECTION",
                "weight": 3.5
            })
            
    df_edges = pd.DataFrame(edges)
    print(f"Total de Arestas (Relacionamentos) criadas: {len(df_edges)}")
    
    # 3. Geracao de Logs de Acesso & Movimentacao Lateral (35.000+ Eventos)
    print("Gerando 35.000+ eventos de acesso comportamental...")
    start_time = datetime(2026, 8, 1, 8, 0, 0)
    
    # Caminhos de Ataque Conhecidos Injetados (Attack Campaigns)
    attack_paths = [
        {
            "name": "Campanha APT-29: Pass-The-Hash Financeiro",
            "sequence": ["ws-finance-01", "ws-finance-02", "bastion-rdp-01", "dc-corp-primary", "db-prod-erp"],
            "type": "Pass-The-Hash"
        },
        {
            "name": "Campanha BlackCat: Ransomware via SMB e Bastion",
            "sequence": ["ws-sales-02", "srv-file-smb", "bastion-ssh-01", "cloud-kms-vault"],
            "type": "Ransomware-Spread"
        },
        {
            "name": "Campanha Insider / Kerberoasting",
            "sequence": ["ws-dev-03", "srv-git-enterprise", "entra-id-sync", "dc-corp-backup", "db-cust-sql"],
            "type": "Kerberoasting"
        }
    ]
    
    events = []
    protocols_map = {
        "SMB_SHARE_MOUNT": ("SMB", 445),
        "HTTP_PROXY": ("HTTPS", 443),
        "GIT_SSH_ACCESS": ("SSH", 22),
        "CAN_SSH_TO": ("SSH", 22),
        "CAN_RDP_TO": ("RDP", 3389),
        "ADMINS_ON": ("Kerberos/RPC", 135),
        "DB_ADMIN_CONSOLE": ("TNS/SQL", 1521),
        "SSH_TUNNEL": ("SSH", 2222),
        "LAN_PEER_CONNECTION": ("SMB/RPC", 445)
    }
    
    node_tier_dict = {n["id"]: n["tier"] for n in nodes}
    
    # 3.1 Eventos Normais de Operacao Corporativa (~34.000 eventos)
    total_events = 35000
    num_normal = 33800
    
    for _ in range(num_normal):
        edge = random.choice(edges)
        ts = start_time + timedelta(minutes=random.randint(1, 45000))
        is_off_hours = 1 if (ts.hour < 7 or ts.hour > 20 or ts.weekday() >= 5) else 0
        
        proto, port = protocols_map.get(edge["type"], ("TCP", 443))
        dur = float(np.random.exponential(15.0) + 0.5)
        bytes_tx = float(np.random.lognormal(mean=8.5, sigma=1.5))
        failed_auth = int(np.random.choice([0, 1, 2], p=[0.96, 0.035, 0.005]))
        
        src_tier = node_tier_dict[edge["source"]]
        dst_tier = node_tier_dict[edge["target"]]
        priv_delta = src_tier - dst_tier # Se positivo, esta tentando acessar nó de maior privilégio
        
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source_node": edge["source"],
            "target_node": edge["target"],
            "relationship": edge["type"],
            "protocol": proto,
            "port": port,
            "source_tier": src_tier,
            "target_tier": dst_tier,
            "privilege_delta": priv_delta,
            "bytes_transferred": round(bytes_tx, 1),
            "duration_sec": round(dur, 2),
            "failed_auth_count": failed_auth,
            "is_off_hours": is_off_hours,
            "is_lateral_movement": 0,
            "attack_campaign": "None"
        })
        
    # 3.2 Injeção das Campanhas de Ataque (Movimentação Lateral Maliciosa) (~1.200 eventos)
    for camp in attack_paths:
        seq = camp["sequence"]
        # Executar 80 rodadas de ataque ao longo do mês
        for r in range(80):
            attack_start = start_time + timedelta(hours=random.randint(24, 600))
            for hop_idx in range(len(seq) - 1):
                s = seq[hop_idx]
                t = seq[hop_idx + 1]
                t_event = attack_start + timedelta(minutes=hop_idx * random.randint(4, 18))
                
                # Comportamento malicioso: falhas de autenticação prévias, horários fora do expediente, salto abrupto de privilégio
                failed_auth = random.randint(3, 14) if hop_idx > 1 else random.randint(1, 4)
                dur = float(np.random.uniform(40.0, 300.0))
                bytes_tx = float(np.random.uniform(50000.0, 2500000.0)) # Exfiltração ou dump de credenciais
                is_off_hours = 1 if random.random() < 0.75 else 0
                
                src_tier = node_tier_dict[s]
                dst_tier = node_tier_dict[t]
                priv_delta = src_tier - dst_tier
                
                events.append({
                    "timestamp": t_event.strftime("%Y-%m-%d %H:%M:%S"),
                    "source_node": s,
                    "target_node": t,
                    "relationship": "LATERAL_TRAVERSAL",
                    "protocol": "RDP" if dst_tier == 0 else "SMB",
                    "port": 3389 if dst_tier == 0 else 445,
                    "source_tier": src_tier,
                    "target_tier": dst_tier,
                    "privilege_delta": priv_delta,
                    "bytes_transferred": round(bytes_tx, 1),
                    "duration_sec": round(dur, 2),
                    "failed_auth_count": failed_auth,
                    "is_off_hours": is_off_hours,
                    "is_lateral_movement": 1,
                    "attack_campaign": camp["type"]
                })
                
    df_events = pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)
    
    os.makedirs("data", exist_ok=True)
    df_nodes.to_csv("data/network_nodes.csv", index=False)
    df_edges.to_csv("data/network_edges.csv", index=False)
    df_events.to_csv("data/auth_events.csv", index=False)
    
    with open("data/attack_scenarios.json", "w", encoding="utf-8") as f:
        json.dump(attack_paths, f, indent=2, ensure_ascii=False)
        
    print(f"Sucesso! Gerados {len(df_nodes)} nós, {len(df_edges)} arestas e {len(df_events):,} eventos comportamentais.")
    print("Distribuição de classes (0: Normal, 1: Movimentação Lateral Maliciosa):")
    print(df_events['is_lateral_movement'].value_counts())

if __name__ == "__main__":
    generate_cybergraph_data()
