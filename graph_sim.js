// graph_sim.js - Motor de Simulação Visual de Grafos & Zero-Trust
// Autor: Jhonny Brasiliano da Silva

let graphData = { nodes: [], edges: [] };
let canvas, ctx;
let width, height;
let transform = { x: 0, y: 0, k: 1 };
let isDragging = false;
let draggedNode = null;
let hoveredNode = null;
let lastMouse = { x: 0, y: 0 };
let activeAttackPath = null;
let pulseStep = 0;
let isSevered = false;

document.addEventListener("DOMContentLoaded", async () => {
  canvas = document.getElementById("networkCanvas");
  ctx = canvas.getContext("2d");
  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);

  try {
    const res = await fetch("data/graph_topology.json");
    if (res.ok) {
      graphData = await res.json();
    }
  } catch (e) {
    console.warn("Utilizando dados de topologia de fallback.", e);
  }

  if (!graphData.nodes || graphData.nodes.length === 0) {
    graphData = generateFallbackGraph();
  }

  populateSelectors();
  initCanvasEvents();
  initCharts();
  requestAnimationFrame(renderLoop);
});

function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  width = rect.width;
  height = rect.height;
  canvas.width = width * window.devicePixelRatio;
  canvas.height = height * window.devicePixelRatio;
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
}

function generateFallbackGraph() {
  const nodes = [
    { id: "ws-finance-01", label: "Workstation Finance 01", zone: "Endpoint_Finance", tier: 3, criticality: 4, pagerank: 0.015, betweenness: 0.002, blast_radius: 9, x: 120, y: 180 },
    { id: "ws-dev-01", label: "Workstation Dev 01", zone: "Endpoint_Dev", tier: 3, criticality: 3, pagerank: 0.018, betweenness: 0.003, blast_radius: 8, x: 120, y: 320 },
    { id: "ws-sales-01", label: "Workstation Sales 01", zone: "Endpoint_Sales", tier: 3, criticality: 2, pagerank: 0.012, betweenness: 0.001, blast_radius: 6, x: 120, y: 460 },
    { id: "srv-file-smb", label: "File Share SMB", zone: "Core_Servers", tier: 1, criticality: 6, pagerank: 0.032, betweenness: 0.008, blast_radius: 4, x: 380, y: 220 },
    { id: "bastion-rdp-01", label: "Bastion Jump RDP", zone: "Bastion", tier: 1, criticality: 8, pagerank: 0.065, betweenness: 0.024, blast_radius: 4, x: 480, y: 340 },
    { id: "bastion-ssh-01", label: "Bastion Jump SSH", zone: "Bastion", tier: 1, criticality: 8, pagerank: 0.048, betweenness: 0.010, blast_radius: 2, x: 480, y: 480 },
    { id: "dc-corp-primary", label: "Primary Domain Controller (AD)", zone: "Identity", tier: 0, criticality: 10, pagerank: 0.088, betweenness: 0.015, blast_radius: 2, x: 740, y: 260 },
    { id: "db-prod-erp", label: "Production ERP Database", zone: "Crown_Jewels", tier: 0, criticality: 10, pagerank: 0.095, betweenness: 0.001, blast_radius: 0, x: 740, y: 420 }
  ];
  const edges = [
    { source: "ws-finance-01", target: "srv-file-smb", type: "SMB_MOUNT" },
    { source: "ws-finance-01", target: "bastion-rdp-01", type: "CAN_RDP_TO" },
    { source: "ws-dev-01", target: "bastion-ssh-01", type: "CAN_SSH_TO" },
    { source: "ws-sales-01", target: "srv-file-smb", type: "SMB_MOUNT" },
    { source: "bastion-rdp-01", target: "dc-corp-primary", type: "ADMINS_ON" },
    { source: "bastion-rdp-01", target: "db-prod-erp", type: "DB_ADMIN_CONSOLE" },
    { source: "bastion-ssh-01", target: "db-prod-erp", type: "SSH_TUNNEL" }
  ];
  return { nodes, edges };
}

function getNodeColor(node) {
  if (node.zone === "Identity") return "#f43f5e"; // Vermelho / Rose (Domain Controllers)
  if (node.zone === "Crown_Jewels") return "#fbbf24"; // Dourado (Bancos de Dados & Vaults)
  if (node.zone === "Bastion") return "#00f2fe"; // Ciano neon (Jump Hosts)
  if (node.zone === "Edge") return "#10b981"; // Esmeralda (Firewall, VPN)
  if (node.tier === 1) return "#c084fc"; // Roxo (Servidores Internos)
  return "#3b82f6"; // Azul (Workstations / Endpoints)
}

function populateSelectors() {
  const selEntry = document.getElementById("selectEntryPoint");
  const selTarget = document.getElementById("selectTarget");
  if (!selEntry || !selTarget) return;

  selEntry.innerHTML = "";
  selTarget.innerHTML = "";

  graphData.nodes.forEach(n => {
    if (n.tier === 3 || n.zone.includes("Endpoint")) {
      const opt = document.createElement("option");
      opt.value = n.id;
      opt.textContent = `${n.label} (${n.id})`;
      selEntry.appendChild(opt);
    }
    if (n.tier === 0 || n.zone === "Crown_Jewels" || n.zone === "Identity") {
      const opt = document.createElement("option");
      opt.value = n.id;
      opt.textContent = `${n.label} [Tier 0]`;
      selTarget.appendChild(opt);
    }
  });

  selEntry.value = "ws-finance-01";
  selTarget.value = "db-prod-erp";
}

function initCanvasEvents() {
  canvas.addEventListener("mousedown", (e) => {
    const pt = getCanvasCoords(e);
    const node = findNodeAt(pt.x, pt.y);
    if (node) {
      draggedNode = node;
    } else {
      isDragging = true;
      lastMouse = { x: e.clientX, y: e.clientY };
    }
  });

  window.addEventListener("mousemove", (e) => {
    const pt = getCanvasCoords(e);
    hoveredNode = findNodeAt(pt.x, pt.y);

    if (draggedNode) {
      draggedNode.x = pt.x;
      draggedNode.y = pt.y;
    } else if (isDragging) {
      transform.x += e.clientX - lastMouse.x;
      transform.y += e.clientY - lastMouse.y;
      lastMouse = { x: e.clientX, y: e.clientY };
    }
  });

  window.addEventListener("mouseup", () => {
    draggedNode = null;
    isDragging = false;
  });

  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    transform.k = Math.max(0.5, Math.min(2.5, transform.k * zoomFactor));
  });
}

function getCanvasCoords(e) {
  const rect = canvas.getBoundingClientRect();
  const screenX = e.clientX - rect.left;
  const screenY = e.clientY - rect.top;
  return {
    x: (screenX - transform.x) / transform.k,
    y: (screenY - transform.y) / transform.k
  };
}

function findNodeAt(x, y) {
  for (let i = graphData.nodes.length - 1; i >= 0; i--) {
    const n = graphData.nodes[i];
    const dx = n.x - x;
    const dy = n.y - y;
    if (Math.sqrt(dx * dx + dy * dy) <= 18) {
      return n;
    }
  }
  return null;
}

// Simulação de Ataque Preditivo
window.simulateAttack = function() {
  const entryId = document.getElementById("selectEntryPoint").value;
  const targetId = document.getElementById("selectTarget").value;
  isSevered = false;

  // Busca o menor caminho no grafo
  const path = findShortestPath(entryId, targetId);
  activeAttackPath = path;
  pulseStep = 0;

  const alertBox = document.getElementById("attackAlertBox");
  const alertTitle = document.getElementById("alertTitle");
  const alertDesc = document.getElementById("alertDesc");
  const playbookText = document.getElementById("playbookRecommendation");
  const btnSever = document.getElementById("btnSeverChokepoint");

  if (path && path.length > 1) {
    const chokepoint = path.find(n => n.includes("bastion") || n.includes("smb") || n.includes("entra")) || path[1];
    
    alertBox.style.display = "block";
    alertTitle.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Alerta Preditivo: Rota de Movimentação Lateral Detectada (${path.length - 1} saltos)`;
    alertDesc.innerHTML = `O invasor comprometeu <strong>${entryId}</strong> e está utilizando técnicas de Pass-the-Hash / Abuso de Sessão para alcançar <strong>${targetId}</strong> através do nó de estrangulamento (Chokepoint) <strong>${chokepoint}</strong>.`;
    playbookText.innerHTML = `🛡️ Playbook Zero-Trust: Isolar aresta de tráfego entre [${path[0]} ➔ ${path[1]}] e revogar credenciais do chokepoint [${chokepoint}].`;
    
    btnSever.style.display = "inline-flex";
    btnSever.dataset.choke = chokepoint;
    btnSever.dataset.src = path[0];
  } else {
    alertBox.style.display = "block";
    alertTitle.innerHTML = `<i class="fa-solid fa-circle-check" style="color: #10b981;"></i> Nenhuma Rota Direta Localizada`;
    alertDesc.innerHTML = `A política de segmentação atual já impede que <strong>${entryId}</strong> alcance <strong>${targetId}</strong> diretamente.`;
    btnSever.style.display = "none";
  }
};

window.severChokepoint = function() {
  isSevered = true;
  activeAttackPath = null;

  const alertTitle = document.getElementById("alertTitle");
  const alertDesc = document.getElementById("alertDesc");
  const playbookText = document.getElementById("playbookRecommendation");
  const btnSever = document.getElementById("btnSeverChokepoint");

  alertTitle.innerHTML = `<i class="fa-solid fa-shield-halved" style="color: #10b981;"></i> Zero-Trust Enforced: Movimentação Lateral Neutralizada!`;
  alertDesc.innerHTML = `A política de microssegmentação dinâmica cortou o ponto de estrangulamento da rede. O invasor foi contido na sub-rede de origem sem conseguir alcançar os ativos Tier 0.`;
  playbookText.innerHTML = `✅ Status: Raio de Destruição (Blast Radius) reduzido a 0 ativos críticos. Host isolado em quarentena via EDR.`;
  btnSever.style.display = "none";
};

function findShortestPath(startId, endId) {
  const queue = [[startId]];
  const visited = new Set([startId]);

  while (queue.length > 0) {
    const currentPath = queue.shift();
    const currentNode = currentPath[currentPath.length - 1];

    if (currentNode === endId) {
      return currentPath;
    }

    const neighbors = graphData.edges
      .filter(e => e.source === currentNode)
      .map(e => e.target);

    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push([...currentPath, neighbor]);
      }
    }
  }
  return null;
}

// Render Loop
function renderLoop() {
  ctx.save();
  ctx.clearRect(0, 0, width, height);

  ctx.translate(transform.x, transform.y);
  ctx.scale(transform.k, transform.k);

  // 1. Desenhar Arestas
  graphData.edges.forEach(edge => {
    const s = graphData.nodes.find(n => n.id === edge.source);
    const t = graphData.nodes.find(n => n.id === edge.target);
    if (!s || !t) return;

    const isPathEdge = activeAttackPath && 
      activeAttackPath.includes(edge.source) && 
      activeAttackPath.includes(edge.target) &&
      activeAttackPath.indexOf(edge.target) === activeAttackPath.indexOf(edge.source) + 1;

    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);

    if (isPathEdge && !isSevered) {
      ctx.strokeStyle = "#f43f5e";
      ctx.lineWidth = 3.5;
      ctx.setLineDash([8, 4]);
      ctx.lineDashOffset = -pulseStep;
    } else {
      ctx.strokeStyle = "rgba(55, 65, 81, 0.45)";
      ctx.lineWidth = 1;
      ctx.setLineDash([]);
    }
    ctx.stroke();
    ctx.setLineDash([]);
  });

  // 2. Desenhar Nós
  pulseStep = (pulseStep + 0.5) % 100;

  graphData.nodes.forEach(node => {
    const isCompromised = activeAttackPath && activeAttackPath.includes(node.id) && !isSevered;
    const isHovered = hoveredNode && hoveredNode.id === node.id;
    const nodeColor = getNodeColor(node);
    const radius = node.tier === 0 ? 14 : (node.tier === 1 ? 11 : 8);

    // Glow e Anel de Pulso em Nós Comprometidos
    if (isCompromised) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius + 6 + (Math.sin(pulseStep * 0.1) * 3), 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(244, 63, 94, 0.6)";
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Corpo do Nó
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = isCompromised ? "#f43f5e" : nodeColor;
    ctx.shadowColor = isCompromised ? "#f43f5e" : nodeColor;
    ctx.shadowBlur = isHovered ? 25 : (node.tier === 0 ? 15 : 6);
    ctx.fill();
    ctx.shadowBlur = 0;

    // Borda
    ctx.strokeStyle = isHovered ? "#ffffff" : "#0d121d";
    ctx.lineWidth = 2;
    ctx.stroke();

    // Rótulo
    if (transform.k > 0.75 || node.tier <= 1 || isHovered || isCompromised) {
      ctx.font = `${isHovered ? 'bold ' : ''}11px 'Plus Jakarta Sans', sans-serif`;
      ctx.fillStyle = isCompromised ? "#fca5a5" : (isHovered ? "#ffffff" : "#cbd5e1");
      ctx.textAlign = "center";
      ctx.fillText(node.label || node.id, node.x, node.y + radius + 14);
    }
  });

  // Tooltip
  if (hoveredNode) {
    drawTooltip(hoveredNode);
  }

  ctx.restore();
  requestAnimationFrame(renderLoop);
}

function drawTooltip(node) {
  const text = `${node.label} (${node.zone})`;
  const sub = `Tier: ${node.tier} | Criticidade: ${node.criticality}/10 | Blast Radius: ${node.blast_radius} nós`;
  const sub2 = `PageRank: ${node.pagerank} | Betweenness: ${node.betweenness}`;
  
  ctx.font = "bold 12px 'Plus Jakarta Sans'";
  const w1 = ctx.measureText(text).width;
  ctx.font = "11px 'Plus Jakarta Sans'";
  const w2 = ctx.measureText(sub).width;
  const boxW = Math.max(w1, w2) + 24;
  const boxH = 64;
  const boxX = node.x - boxW / 2;
  const boxY = node.y - 75;

  ctx.fillStyle = "rgba(13, 18, 29, 0.95)";
  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.roundRect(boxX, boxY, boxW, boxH, 8);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = "#ffffff";
  ctx.font = "bold 12px 'Plus Jakarta Sans'";
  ctx.textAlign = "center";
  ctx.fillText(text, node.x, boxY + 18);

  ctx.fillStyle = "#94a3b8";
  ctx.font = "11px 'Plus Jakarta Sans'";
  ctx.fillText(sub, node.x, boxY + 36);

  ctx.fillStyle = "#00f2fe";
  ctx.font = "10px 'JetBrains Mono'";
  ctx.fillText(sub2, node.x, boxY + 52);
}

// Inicializar Gráficos Chart.js
function initCharts() {
  // Gráfico de Campanhas de Ataque
  const ctxCampaign = document.getElementById("campaignPieChart").getContext("2d");
  new Chart(ctxCampaign, {
    type: "doughnut",
    data: {
      labels: ["Pass-The-Hash", "Ransomware-Spread", "Kerberoasting"],
      datasets: [{
        data: [320, 320, 240],
        backgroundColor: ["#f43f5e", "#fbbf24", "#00f2fe"],
        borderColor: "#0d121d",
        borderWidth: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom", labels: { color: "#94a3b8" } }
      },
      cutout: "70%"
    }
  });

  // Gráfico de Importância de Features Topológicas
  const ctxFeat = document.getElementById("graphFeaturesChart").getContext("2d");
  new Chart(ctxFeat, {
    type: "bar",
    data: {
      labels: [
        "Bytes Transferred",
        "Failed Auth Count",
        "Connection Duration (s)",
        "Off-Hours + Failed Auth",
        "Source Blast Radius",
        "Exfiltration Speed",
        "PageRank Delta"
      ],
      datasets: [{
        data: [0.3353, 0.2373, 0.2283, 0.0958, 0.0330, 0.0168, 0.0124],
        backgroundColor: [
          "rgba(244, 63, 94, 0.85)",
          "rgba(251, 191, 36, 0.85)",
          "rgba(0, 242, 254, 0.85)",
          "rgba(192, 132, 252, 0.85)",
          "rgba(16, 185, 129, 0.85)",
          "rgba(59, 130, 246, 0.85)",
          "rgba(148, 163, 184, 0.85)"
        ],
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#94a3b8", callback: v => (v * 100) + "%" }, grid: { color: "rgba(55, 65, 81, 0.3)" } },
        y: { ticks: { color: "#e2e8f0" }, grid: { display: false } }
      }
    }
  });
}
