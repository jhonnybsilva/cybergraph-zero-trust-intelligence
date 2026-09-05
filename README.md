# 🛡️ CyberGraph AI: Inteligência de Grafos & Detecção Preditiva de Movimentação Lateral em Arquiteturas Zero-Trust

<p align="center">
  <a href="https://jhonnybsilva.github.io/cybergraph-zero-trust-intelligence/">
    <strong>🌐 Clique aqui para acessar o Simulador Visual de Grafos Online (GitHub Pages)</strong>
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/NetworkX-Graph_Theory-00F2FE?style=for-the-badge" alt="NetworkX">
  <img src="https://img.shields.io/badge/Zero--Trust-Architecture-F43F5E?style=for-the-badge" alt="Zero-Trust">
  <img src="https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/F1--Score-99.1%25-success?style=for-the-badge" alt="F1-Score">
  <img src="https://img.shields.io/badge/Status-Concluído-blue?style=for-the-badge" alt="Status">
</p>

---

## 📌 Visão Geral da Inovação

A maioria esmagadora das análises de dados em cibersegurança foca em tabelas estáticas e registros lineares isolados. O **CyberGraph AI** rompe essa barreira ao aplicar **Graph Data Science (Ciência de Dados em Grafos)** e **Teoria dos Grafos** para modelar redes corporativas como grafos direcionados ponderados $G = (V, E, W)$.

O sistema monitora relações de confiança, privilégios de acesso e sessões de autenticação, identificando **Pontos de Estrangulamento (Chokepoints)**, calculando o **Raio de Destruição (Blast Radius)** de cada ativo e prevendo rotas de ataque e movimentação lateral (*Pass-the-Hash*, *Kerberoasting*, *Ransomware*) com **100% de precisão**.

O projeto conta com um **Simulador Visual de Redes em Canvas** no navegador (GitHub Pages), permitindo a simulação interativa de invasões e o corte de rotas maliciosas em tempo real via microssegmentação Zero-Trust.

---

## 🏗️ Arquitetura da Solução

```mermaid
flowchart TD
    subgraph Topology [1. Modelagem Topológica de Ativos]
        A[46 Nós Corporativos:\nTier 0 DC/DBs, Bastions, Endpoints] --> B[120 Relações de Confiança:\nRDP, SSH, SMB, Kerberos, LDAP]
    end

    subgraph Graph_Analytics [2. Motor de Teoria dos Grafos]
        B --> C[(SQLite Database:\ncybergraph_security.db)]
        C --> D[graph_engine.py\nCálculo de PageRank & Betweenness]
        D --> E[Algoritmo de Blast Radius\n& Menor Caminho Dijkstra]
    end

    subgraph Machine_Learning [3. Inteligência Preditiva]
        E --> F[Engenharia de Features de Grafo:\nDelta de Privilégio, Taxa de Exfiltração]
        F --> G[HistGradientBoosting Classifier\nF1-Score: 99.1% | Precisão: 100%]
        F --> H[Isolation Forest\nDetecção de Anomalias Zero-Day]
    end

    subgraph Visual_SOC [4. Simulador Interativo]
        G & H --> I[Dashboard Cyber-SOC em Canvas\nTraçado Dinâmico de Rotas de Ataque]
        I --> J[Deploy no GitHub Pages]
    end
```

---

## 🔬 Fundamentos Matemáticos & Algorítmicos

### 1. PageRank de Privilégio Estrutural ($PR$)
Mede a influência indireta e o risco acumulado que um nó exerce sobre o domínio corporativo:
$$PR(u) = \frac{1 - d}{N} + d \sum_{v \in \mathcal{M}(u)} \frac{PR(v)}{L(v)}$$

### 2. Centralidade de Intermediação (Detecção de Chokepoints)
Identifica quais máquinas funcionam como pontes obrigatórias entre sub-redes para que um invasor alcance o controlador de domínio:
$$C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$
*Descoberta chave:* O nó `bastion-rdp-01` possui a maior centralidade ($0,02424$), sendo o alvo primário de qualquer invasão lateral.

### 3. Raio de Destruição (Blast Radius em $k$-Saltos)
Calcula a quantidade de nós e o valor financeiro/operacional dos ativos que um atacante pode comprometer caso o host $v$ seja violado:
$$\text{BlastRadius}(v) = \sum_{u \in \text{Reachable}_{\le 2}(v)} \text{Criticality}(u)$$

---

## 📊 Métricas e Performance dos Modelos

| Métrica | Classificador Supervisionado (Zero-Trust Interceptor) | Detector Não-Supervisionado (Isolation Forest) |
| :--- | :---: | :---: |
| **Algoritmo** | `HistGradientBoostingClassifier` | `IsolationForest` ($c=0.03$) |
| **ROC-AUC Score** | **1.0000** | — |
| **Precisão (Precision)** | **100.0%** (0 Falsos Positivos) | — |
| **Recall (Sensibilidade)** | **98.30%** (173/176 ataques capturados) | — |
| **F1-Score** | **0.9914** | **0.8693** |

*Impacto Operacional:* Em 6.760 amostras de teste legítimas, **nenhum falso alarme foi gerado**, garantindo que a equipe de Resposta a Incidentes (DFIR/SOC) atue apenas em ameaças reais confirmadas.

---

## 🗄️ Modelagem Relacional (SQLite)

O banco de dados `data/cybergraph_security.db` estrutura a topologia em quatro tabelas relacionais com índices em chaves de alta frequência:

* **`network_nodes`:** Cadastro dos 46 ativos, zonas, tiers de privilégio (0 a 3) e sistema operacional.
* **`network_edges`:** 120 arestas direcionadas mapeando permissões de RDP, SSH, SMB e replicação de AD.
* **`graph_metrics`:** Métricas pré-computadas de PageRank, Betweenness e Blast Radius.
* **`auth_events`:** 34.680 registros de conexões com telemetria de bytes transferidos, falhas de autenticação e flag de movimentação lateral.

---

## 💻 Estrutura do Repositório

```plaintext
├── data/
│   ├── network_nodes.csv             # Cadastro de nós e ativos da rede
│   ├── network_edges.csv             # Relacionamentos de confiança e arestas
│   ├── auth_events.csv               # 34.680 eventos comportamentais
│   ├── node_graph_metrics.csv        # Métricas calculadas de Teoria dos Grafos
│   ├── graph_topology.json           # Topologia visual exportada para o Canvas
│   ├── attack_scenarios.json         # Campanhas de ataque catalogadas
│   └── cybergraph_security.db        # Banco de dados relacional SQLite
├── models/
│   ├── lateral_movement_detector.joblib # Modelo preditivo treinado
│   ├── graph_anomaly_isolation.joblib   # Isolation Forest treinado
│   └── metrics.json                  # Matriz de confusão e métricas
├── generator.py                      # Geração da topologia e simulação de eventos
├── graph_engine.py                   # Processamento com NetworkX e SQLite
├── pipeline.py                       # Engenharia de atributos de grafos e ML
├── graph_sim.js                      # Motor de física e visualização em Canvas
├── index.html                        # Dashboard Cyber-SOC (GitHub Pages)
├── style.css                         # Design Cyberpunk / Dark SOC
└── README.md                         # Documentação completa do projeto
```

---

## ⚙️ Como Executar Localmente

### 1. Clonar o repositório
```bash
git clone https://github.com/jhonnybsilva/cybergraph-zero-trust-intelligence.git
cd cybergraph-zero-trust-intelligence
```

### 2. Instalar dependências
```bash
pip install networkx pandas numpy scikit-learn joblib
```

### 3. Gerar a topologia e métricas de grafos
```bash
python generator.py
python graph_engine.py
```

### 4. Executar o pipeline preditivo de Machine Learning
```bash
python pipeline.py
```

### 5. Abrir o Simulador Visual
Abra o arquivo `index.html` no navegador ou inicie um servidor local:
```bash
python -m http.server 3000
```
Acesse `http://localhost:3000`.

---

## 👨‍💻 Sobre o Autor

**Jhonny Brasiliano da Silva**  
- 🎓 **Pós-Graduação:** Data Analytics — **FIAP**
- 🎓 **Graduação:** Análise e Desenvolvimento de Sistemas — **UNINOVE**
- 🎓 **Técnico:** Redes de Computadores — **ETEC Embu das Artes**
- 💼 **Atuação Profissional:** Analista de Infraestrutura na **HSR Specialist Researchers**
- 🌐 **Portfólio Online:** [jhonnybsilva.github.io/portfolio](https://jhonnybsilva.github.io/portfolio/)
- 💼 **LinkedIn:** [linkedin.com/in/jhonnybrasilianodasilva](https://www.linkedin.com/in/jhonnybrasilianodasilva)
- 🐙 **GitHub:** [github.com/jhonnybsilva](https://github.com/jhonnybsilva)
