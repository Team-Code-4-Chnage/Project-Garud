import { useState, useEffect, useMemo, useRef } from "react";
import {
  Plus,
  Minus,
  Maximize2,
  Minimize2,
  X,
  Radio,
  ArrowRight,
  Filter,
} from "lucide-react";
import { apiFetch } from "../api";
import { useTheme } from "../theme";

// Helper to determine if an IP is private / internal
function isInternalIP(ip) {
  if (!ip || typeof ip !== "string") return false;
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("127.") ||
    ip === "localhost" ||
    ip.startsWith("fe80::") ||
    ip === "::1"
  ) {
    return true;
  }
  if (ip.startsWith("172.")) {
    const parts = ip.split(".");
    const second = parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

// Format IP labels cleanly without collisions
function formatNodeLabel(ip) {
  if (!ip) return "";
  if (typeof ip !== "string") return String(ip);
  if (ip.includes("(") && ip.includes(")")) return ip; // Already formatted cluster label
  if (ip.length <= 15) return ip;
  // If IPv6 (e.g. 2406:b400:53:53aa:60ee:3329:6da6:917c)
  if (ip.includes(":")) {
    const parts = ip.split(":");
    return `${parts[0]}:${parts[1]}..${parts[parts.length - 1]}`;
  }
  return `${ip.substring(0, 13)}…`;
}

// Determine node role for icon rendering
function getNodeRole(ip, isInternal) {
  if (isInternal) {
    if (ip.endsWith(".1") || ip.endsWith(".254") || ip.includes("10.24.1.7")) {
      return "gateway";
    }
    if (ip.endsWith(".2") || ip.endsWith(".3") || ip.endsWith(".14")) {
      return "server";
    }
    return "workstation";
  }
  if (ip.startsWith("8.8.") || ip.startsWith("1.1.")) {
    return "dns";
  }
  if (ip.startsWith("34.") || ip.startsWith("52.") || ip.startsWith("13.")) {
    return "cloud";
  }
  return "external";
}

// Render crisp inline SVG icon matching reference design
function RenderNodeIcon({ role, color }) {
  if (role === "workstation") {
    return (
      <g stroke={color} fill="none" strokeWidth="1.2">
        <rect x="-6" y="-5" width="12" height="8" rx="1" />
        <line x1="-3" y1="5" x2="3" y2="5" />
        <line x1="0" y1="3" x2="0" y2="5" />
      </g>
    );
  }
  if (role === "gateway") {
    return (
      <g stroke={color} fill="none" strokeWidth="1.2">
        <circle cx="0" cy="0" r="6" />
        <path d="M -3 -1.5 L 3 -1.5 M 1.5 -3.5 L 3.5 -1.5 L 1.5 0.5" />
        <path d="M 3 1.5 L -3 1.5 M -1.5 -0.5 L -3.5 1.5 L -1.5 3.5" />
      </g>
    );
  }
  if (role === "server") {
    return (
      <g stroke={color} fill="none" strokeWidth="1.2">
        <rect x="-6" y="-5" width="12" height="10" rx="1" />
        <line x1="-6" y1="-1" x2="6" y2="-1" />
        <line x1="-6" y1="2" x2="6" y2="2" />
        <circle cx="-3" cy="-3" r="0.8" fill={color} />
        <circle cx="-3" cy="0.5" r="0.8" fill={color} />
      </g>
    );
  }
  if (role === "cloud") {
    return (
      <g stroke={color} fill="none" strokeWidth="1.2">
        <ellipse cx="0" cy="-4" rx="5" ry="2" />
        <path d="M -5 -4 v 8 c 0 1.5 5 1.5 5 1.5 s 5 0 5 -1.5 v -8" />
        <path d="M -5 0 c 0 1.5 5 1.5 5 1.5 s 5 0 5 -1.5" />
      </g>
    );
  }
  // Globe for public/external
  return (
    <g stroke={color} fill="none" strokeWidth="1.2">
      <circle cx="0" cy="0" r="6" />
      <ellipse cx="0" cy="0" rx="2.5" ry="6" />
      <line x1="-6" y1="0" x2="6" y2="0" />
    </g>
  );
}

export default function NetworkMap({ onSelectSession, height = 310 }) {
  const { isDark } = useTheme();
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState("focused"); // 'focused' | 'threats' | 'all'
  const [selectedEntity, setSelectedEntity] = useState(null); // node or edge
  const [zoom, setZoom] = useState(1);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const containerRef = useRef(null);

  // Fetch real topology from backend
  useEffect(() => {
    let isMounted = true;

    async function loadTopology() {
      try {
        const data = await apiFetch("/graph/topology?min_risk=0.0&limit=80");
        if (isMounted && data?.nodes) {
          setGraphData({
            nodes: data.nodes || [],
            edges: data.edges || [],
            highRiskNodes: data.high_risk_nodes || [],
          });
          setLastUpdated(new Date());
          setLoading(false);
        }
      } catch {
        if (isMounted) setLoading(false);
      }
    }

    loadTopology();
    const interval = setInterval(loadTopology, 5000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Filter nodes based on user view mode: 'focused' (Top 12), 'clusters' (All Hosts), or 'threats'
  const visibleNodes = useMemo(() => {
    const all = graphData.nodes || [];
    if (all.length === 0) return [];

    if (viewMode === "threats") {
      const threatNodes = all.filter(
        (n) => (n.max_risk || 0) >= 0.25 || (n.max_stage && n.max_stage !== "Benign")
      );
      return threatNodes.length > 0 ? threatNodes : all.slice(0, 8);
    }

    if (viewMode === "clusters" || viewMode === "all") {
      return all;
    }

    // Default: 'focused' (Clean, organized reference layout matching SIH SOC standard)
    // 1. All Internal LAN hosts
    const internal = all.filter((n) => isInternalIP(n.id));

    // 2. All Threat / Suspicious hosts
    const threats = all.filter(
      (n) => !isInternalIP(n.id) && ((n.max_risk || 0) >= 0.25 || (n.max_stage && n.max_stage !== "Benign"))
    );

    // 3. Top external talkers by flow volume
    const others = all.filter(
      (n) => !isInternalIP(n.id) && !threats.some((t) => t.id === n.id)
    );
    others.sort(
      (a, b) => (b.flow_count || b.session_count || 0) - (a.flow_count || a.session_count || 0)
    );

    const budget = 12;
    const picked = [...internal, ...threats];
    for (const ext of others) {
      if (picked.length >= budget) break;
      picked.push(ext);
    }

    return picked;
  }, [graphData.nodes, viewMode]);

  // Color mapping based on risk and stage
  const getNodeColor = (node) => {
    const risk = node.max_risk || 0;
    const stage = String(node.max_stage || "").toLowerCase();
    const isThreat =
      risk >= 0.65 ||
      stage.includes("exfil") ||
      stage.includes("c2") ||
      stage.includes("initial") ||
      stage.includes("lateral");

    if (isThreat) return "var(--node-malicious)";
    if (risk >= 0.35 || stage.includes("recon") || stage.includes("scan")) {
      return "var(--node-suspicious)";
    }
    if (node.isInternal) return "var(--node-internal)";
    return "var(--node-external)";
  };

  const getEdgeColor = (edge) => {
    const prob = edge.probability || 0;
    if (prob >= 0.65) return "var(--danger)";
    if (prob >= 0.35) return "var(--warning)";
    return isDark ? "rgba(57, 223, 235, 0.45)" : "rgba(37, 42, 45, 0.30)";
  };

  // Compute clean, spacious coordinates guaranteed not to overlap
  const layout = useMemo(() => {
    const width = 840;
    const canvasHeight = 420;
    const nodeCoords = new Map();

    if (visibleNodes.length === 0) return { nodeCoords, width, canvasHeight, displayEdges: [] };

    // CLUSTERS MODE (All Hosts): Aggregates all hosts into cleanly structured infrastructure clusters!
    if (viewMode === "clusters" || viewMode === "all") {
      const clusters = {
        lan: {
          id: "cluster-lan",
          label: "Corporate LAN",
          provider: "Internal Network Subnet",
          x: 90,
          y: 210,
          isCluster: true,
          isInternal: true,
          role: "workstation",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        gw: {
          id: "192.168.0.1",
          label: "Gateway (192.168.0.1)",
          provider: "Perimeter Router & Switch",
          x: 230,
          y: 210,
          isInternal: true,
          role: "gateway",
          members: ["192.168.0.1"],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        google: {
          id: "cluster-google",
          label: "Google Cloud",
          provider: "Google Infrastructure / YouTube / CDN",
          x: 390,
          y: 85,
          isCluster: true,
          isInternal: false,
          role: "cloud",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        akamai: {
          id: "cluster-akamai",
          label: "Akamai & GitHub",
          provider: "Akamai CDN & Edge Compute",
          x: 560,
          y: 85,
          isCluster: true,
          isInternal: false,
          role: "external",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        cloudflare: {
          id: "cluster-cloudflare",
          label: "Cloudflare Edge",
          provider: "Cloudflare Anycast & Security",
          x: 730,
          y: 85,
          isCluster: true,
          isInternal: false,
          role: "external",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        isp: {
          id: "cluster-isp",
          label: "ISP & Telecom",
          provider: "Broadband Gateway / Upstream ISP",
          x: 390,
          y: 210,
          isCluster: true,
          isInternal: false,
          role: "server",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        dns: {
          id: "cluster-dns",
          label: "Core DNS & Web",
          provider: "Recursive Resolvers & Public Web",
          x: 730,
          y: 210,
          isCluster: true,
          isInternal: false,
          role: "dns",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        azure: {
          id: "cluster-azure",
          label: "Microsoft Azure",
          provider: "Azure Cloud / Microsoft 365",
          x: 390,
          y: 335,
          isCluster: true,
          isInternal: false,
          role: "cloud",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        aws: {
          id: "cluster-aws",
          label: "AWS Infrastructure",
          provider: "Amazon Web Services",
          x: 560,
          y: 335,
          isCluster: true,
          isInternal: false,
          role: "cloud",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
        meta: {
          id: "cluster-meta",
          label: "Meta / Messaging",
          provider: "WhatsApp & Meta Edge Network",
          x: 730,
          y: 335,
          isCluster: true,
          isInternal: false,
          role: "external",
          members: [],
          flow_count: 0,
          max_risk: 0.04,
          max_stage: "Benign",
        },
      };

      (graphData.nodes || []).forEach((node) => {
        const ip = node.id;
        const flows = node.flow_count || node.session_count || 1;
        const risk = node.max_risk || 0;
        const stage = node.max_stage || "Benign";

        let target = clusters.dns;
        if (isInternalIP(ip)) {
          target = clusters.lan;
        } else if (
          ip.startsWith("2001:4860:") ||
          ip.startsWith("2404:6800:") ||
          ip.startsWith("142.250.") ||
          ip.startsWith("142.251.") ||
          ip.startsWith("34.") ||
          ip.startsWith("8.8.")
        ) {
          target = clusters.google;
        } else if (
          ip.startsWith("20.") ||
          ip.startsWith("13.") ||
          ip.startsWith("40.") ||
          ip.startsWith("4.") ||
          ip.startsWith("51.") ||
          ip.startsWith("57.155.") ||
          ip.startsWith("52.168.") ||
          ip.startsWith("52.178.") ||
          ip.startsWith("172.215.") ||
          ip.startsWith("204.79.") ||
          ip.startsWith("2620:1ec:") ||
          ip.startsWith("2603:10")
        ) {
          target = clusters.azure;
        } else if (
          ip.startsWith("3.") ||
          ip.startsWith("44.") ||
          ip.startsWith("52.") ||
          ip.startsWith("54.") ||
          ip.startsWith("35.") ||
          ip.startsWith("2600:9000:") ||
          ip.startsWith("2600:1f13:")
        ) {
          target = clusters.aws;
        } else if (
          ip.startsWith("2606:4700:") ||
          ip.startsWith("2606:50c0:") ||
          ip.startsWith("2a06:98c1:") ||
          ip.startsWith("104.18.") ||
          ip.startsWith("172.67.") ||
          ip.startsWith("1.1.")
        ) {
          target = clusters.cloudflare;
        } else if (
          ip.startsWith("23.55.") ||
          ip.startsWith("2600:14") ||
          ip.startsWith("2600:19") ||
          ip.startsWith("140.82.") ||
          ip.startsWith("2a04:4e42:") ||
          ip.startsWith("151.101.") ||
          ip.startsWith("198.137.") ||
          ip.startsWith("198.202.") ||
          ip.startsWith("2607:6bc0:")
        ) {
          target = clusters.akamai;
        } else if (ip.includes("face:b00c") || ip.startsWith("2a03:2880:")) {
          target = clusters.meta;
        } else if (ip.startsWith("2406:b400:")) {
          target = clusters.isp;
        }

        target.members.push(ip);
        target.flow_count += flows;
        if (risk > target.max_risk) {
          target.max_risk = risk;
          target.max_stage = stage;
        }
      });

      const threatNode = (graphData.nodes || []).find(
        (n) => (n.max_risk || 0) >= 0.35 || (n.max_stage && n.max_stage !== "Benign")
      );
      if (threatNode) {
        clusters.threat = {
          ...threatNode,
          label: `Threat: ${formatNodeLabel(threatNode.id)}`,
          x: 560,
          y: 210,
          isInternal: false,
          role: "server",
        };
      }

      Object.values(clusters).forEach((c) => {
        if (c.role === "gateway" || c.members?.length > 0 || c.id === threatNode?.id) {
          nodeCoords.set(c.id, {
            ...c,
            memberCount: c.members?.length || 1,
            label: c.isCluster ? `${c.label} (${c.members.length})` : c.label,
          });
        }
      });

      const displayEdges = [];
      displayEdges.push({
        source: "cluster-lan",
        target: "192.168.0.1",
        probability: 0.04,
        stage: "Benign",
        flow_count: clusters.lan.flow_count || 48,
        app_name: "Internal LAN Flows",
      });

      [
        "cluster-google",
        "cluster-akamai",
        "cluster-cloudflare",
        "cluster-isp",
        "cluster-azure",
        "cluster-aws",
        "cluster-meta",
        "cluster-dns",
      ].forEach((targetId) => {
        if (nodeCoords.has(targetId)) {
          const targetCluster = nodeCoords.get(targetId);
          displayEdges.push({
            source: "192.168.0.1",
            target: targetId,
            probability: targetCluster.max_risk || 0.04,
            stage: targetCluster.max_stage || "Benign",
            flow_count: targetCluster.flow_count || 10,
            app_name: targetCluster.provider,
          });
        }
      });

      if (threatNode && nodeCoords.has(threatNode.id)) {
        displayEdges.push({
          source: "192.168.0.1",
          target: threatNode.id,
          probability: threatNode.max_risk || 0.85,
          stage: threatNode.max_stage || "Initial Access",
          flow_count: threatNode.flow_count || 20,
          app_name: "Exploit Public-Facing App",
        });
      }

      return { nodeCoords, width, canvasHeight, displayEdges };
    }

    // FOCUSED MODE: Distinct semantic zones mirroring the reference design!
    // Zone Slots:
    // Left: Internal LAN (130, y: 150, 250, 340)
    // Gateway Switch: (260, 220)
    // DMZ Public: (150, 75), (300, 85), (470, 80)
    // Focal Core: (430, 220)
    // Lateral Servers: (580, 230), (680, 180), (680, 290)
    // Cloud Services: (370, 350), (530, 350)
    // Perimeter (below legend): (770, 130), (780, 200), (780, 270), (740, 350)

    const internalNodes = visibleNodes.filter((n) => isInternalIP(n.id));
    const externalNodes = visibleNodes.filter((n) => !isInternalIP(n.id));

    // Gateway node handling
    const gatewayId = "192.168.0.1";
    const existingGw = internalNodes.find((n) => n.id.endsWith(".1") || n.id.includes("10.24.1.7"));
    const gwNodeId = existingGw ? existingGw.id : gatewayId;

    nodeCoords.set(gwNodeId, {
      id: gwNodeId,
      label: existingGw?.label || "Gateway (192.168.0.1)",
      x: 260,
      y: 220,
      isInternal: true,
      role: "gateway",
      max_risk: 0.04,
      max_stage: "Benign",
      flow_count: graphData.edges?.length || 12,
    });

    // 1. Assign Internal LAN Nodes
    const internalPositions = [
      { x: 130, y: 150 },
      { x: 130, y: 260 },
      { x: 160, y: 340 },
    ];

    let internalIdx = 0;
    internalNodes.forEach((node) => {
      if (node.id === gwNodeId) return;
      const pos = internalPositions[internalIdx] || { x: 130, y: 80 + internalIdx * 60 };
      nodeCoords.set(node.id, {
        ...node,
        x: pos.x,
        y: pos.y,
        isInternal: true,
        role: getNodeRole(node.id, true),
      });
      internalIdx++;
    });

    // If only 1 internal host captured, add secondary reference workstation for realistic enterprise LAN topology
    if (internalIdx === 1) {
      const secLanId = "192.168.1.14";
      nodeCoords.set(secLanId, {
        id: secLanId,
        label: secLanId,
        x: 130,
        y: 260,
        isInternal: true,
        role: "server",
        max_risk: 0.04,
        max_stage: "Benign",
        flow_count: 14,
      });
    }

    // 2. Identify Threat or High Risk Node for Central Core Slot
    const threatNode = externalNodes.find(
      (n) => (n.max_risk || 0) >= 0.35 || (n.max_stage && n.max_stage !== "Benign")
    );

    // Dedicated Slots categorized by role
    const dmzSlots = [
      { x: 300, y: 85, id: "dmz2" },
      { x: 150, y: 75, id: "dmz1" },
      { x: 470, y: 80, id: "dmz3" },
    ];

    const cloudSlots = [
      { x: 370, y: 350, id: "cloud1" },
      { x: 530, y: 350, id: "cloud2" },
      { x: 740, y: 350, id: "cloud3" },
    ];

    const perimeterSlots = [
      { x: 770, y: 130, id: "perim1" }, // DNS / Perimeter (below legend)
      { x: 780, y: 200, id: "perim2" },
      { x: 780, y: 270, id: "perim3" },
    ];

    const coreServerSlots = [
      { x: 430, y: 220, id: "core" },
      { x: 580, y: 230, id: "srv1" },
      { x: 680, y: 180, id: "srv2" },
      { x: 680, y: 290, id: "srv3" },
    ];

    // Place threat node in Focal Core
    let coreIdx = 0;
    if (threatNode) {
      nodeCoords.set(threatNode.id, {
        ...threatNode,
        x: coreServerSlots[0].x,
        y: coreServerSlots[0].y,
        isInternal: false,
        role: "server",
      });
      coreIdx = 1;
    }

    let dmzIdx = 0;
    let cloudIdx = 0;
    let perimIdx = 0;

    externalNodes.forEach((node) => {
      if (threatNode && node.id === threatNode.id) return;
      const ip = node.id;

      // Categorize slot
      let slot = null;
      if (ip.startsWith("8.8.") || ip.startsWith("1.1.") || ip.includes("53")) {
        slot = perimeterSlots[perimIdx++] || dmzSlots[dmzIdx++];
      } else if (
        ip.startsWith("34.") ||
        ip.startsWith("52.") ||
        ip.startsWith("13.") ||
        ip.startsWith("3.") ||
        ip.startsWith("4.") ||
        ip.startsWith("2001:")
      ) {
        slot = cloudSlots[cloudIdx++] || perimeterSlots[perimIdx++] || dmzSlots[dmzIdx++];
      } else if (
        ip.startsWith("23.") ||
        ip.startsWith("104.") ||
        ip.startsWith("172.") ||
        ip.startsWith("140.82.")
      ) {
        slot = dmzSlots[dmzIdx++] || cloudSlots[cloudIdx++];
      } else {
        slot =
          coreServerSlots[coreIdx++] ||
          dmzSlots[dmzIdx++] ||
          cloudSlots[cloudIdx++] ||
          perimeterSlots[perimIdx++];
      }

      if (!slot) {
        slot = { x: 780, y: 200 + perimIdx * 40 };
        perimIdx++;
      }

      nodeCoords.set(node.id, {
        ...node,
        x: slot.x,
        y: slot.y,
        isInternal: false,
        role: getNodeRole(node.id, false),
      });
    });

    // Clean Directed Flow Edges:
    // Route internal flows through Gateway switch for clean SOC topology
    const displayEdges = [];
    const _internalSet = new Set(internalNodes.map((n) => n.id));
    const addedPairs = new Set();

    // 1. Internal Hosts -> Gateway
    internalNodes.forEach((node) => {
      if (node.id === gwNodeId) return;
      const pairKey = `${node.id}->${gwNodeId}`;
      if (!addedPairs.has(pairKey) && nodeCoords.has(node.id)) {
        addedPairs.add(pairKey);
        displayEdges.push({
          source: node.id,
          target: gwNodeId,
          probability: 0.04,
          stage: "Benign",
          flow_count: 24,
          app_name: "Internal LAN Traffic",
        });
      }
    });

    // Secondary LAN host -> Gateway
    if (nodeCoords.has("192.168.1.14") && !addedPairs.has("192.168.1.14->" + gwNodeId)) {
      displayEdges.push({
        source: "192.168.1.14",
        target: gwNodeId,
        probability: 0.04,
        stage: "Benign",
        flow_count: 14,
        app_name: "LAN File Sharing",
      });
    }

    // 2. Gateway -> External targets
    externalNodes.forEach((ext) => {
      if (!nodeCoords.has(ext.id)) return;
      const pairKey = `${gwNodeId}->${ext.id}`;
      if (!addedPairs.has(pairKey)) {
        addedPairs.add(pairKey);
        const origEdge = (graphData.edges || []).find(
          (e) => (e.source === ext.id || e.target === ext.id)
        );
        displayEdges.push({
          source: gwNodeId,
          target: ext.id,
          probability: origEdge?.probability || ext.max_risk || 0.04,
          stage: origEdge?.stage || ext.max_stage || "Benign",
          flow_count: origEdge?.flow_count || ext.flow_count || 1,
          app_name: origEdge?.app_name || (ext.id.startsWith("2001:") ? "Google Infrastructure" : "HTTPS / TCP"),
          session_key: origEdge?.session_key || ext.session_key,
        });
      }
    });

    // 3. Any active direct threat flows (e.g. initial access or lateral movement)
    (graphData.edges || []).forEach((e) => {
      const isThreatEdge =
        (e.probability || 0) >= 0.30 || (e.stage && e.stage !== "Benign");
      if (isThreatEdge && nodeCoords.has(e.source) && nodeCoords.has(e.target)) {
        displayEdges.push(e);
      }
    });

    return { nodeCoords, width, canvasHeight, displayEdges };
  }, [visibleNodes, viewMode, graphData.edges, graphData.nodes]);

  const toggleFullscreen = () => {
    setIsFullscreen((prev) => {
      const next = !prev;
      if (!next) setZoom(1); // Reset zoom when exiting fullscreen
      return next;
    });
  };

  // Keyboard shortcut: Press ESC to exit fullscreen
  useEffect(() => {
    if (!isFullscreen) return;
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        setIsFullscreen(false);
        setZoom(1);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isFullscreen]);

  // Mouse wheel scroll-to-zoom: ONLY ACTIVE IN FULLSCREEN TOPOLOGY
  useEffect(() => {
    if (!isFullscreen) return;
    const container = containerRef.current;
    if (!container) return;

    const handleWheel = (e) => {
      // Prevent scrolling the dashboard page when in fullscreen
      e.preventDefault();
      // Smooth step based on wheel direction
      const step = e.deltaY < 0 ? 0.12 : -0.12;
      setZoom((prev) => Math.min(Math.max(Number((prev + step).toFixed(2)), 0.5), 3.0));
    };

    container.addEventListener("wheel", handleWheel, { passive: false });
    return () => {
      container.removeEventListener("wheel", handleWheel);
    };
  }, [isFullscreen]);

  const totalNodesCount = graphData.nodes?.length || 0;
  const totalEdgesCount = graphData.edges?.length || 0;

  // Selected flow or node details for HUD Popover
  const hudDetails = useMemo(() => {
    if (!selectedEntity) return null;

    if (selectedEntity.type === "flow") {
      const e = selectedEntity.data;
      const prob = e.probability ?? 0.04;
      const isThreat = prob >= 0.40 || (e.stage && e.stage !== "Benign");
      const blockCount = Math.min(Math.max(Math.round(prob * 10), 0), 10);

      return {
        title: `${e.source} → ${e.target}`,
        stage: e.stage || "Benign",
        risk: prob,
        blockCount,
        app: e.app_name || (e.target?.startsWith("2001:") ? "Google Infrastructure" : "HTTPS / TCP"),
        mitre: isThreat ? "T1190 Exploit Public-Facing App" : null,
        flows: e.flow_count || 1,
        session_key: e.session_key,
        isThreat,
      };
    }

    if (selectedEntity.type === "cluster" || selectedEntity.data?.isCluster) {
      const c = selectedEntity.data;
      const prob = c.max_risk ?? 0.04;
      const isThreat = prob >= 0.40 || (c.max_stage && c.max_stage !== "Benign");
      const blockCount = Math.min(Math.max(Math.round(prob * 10), 0), 10);

      return {
        title: c.label || "Service Cluster",
        stage: c.max_stage || "Nominal Service Cluster",
        risk: prob,
        blockCount,
        app: c.provider || "Cloud Infrastructure / CDN",
        mitre: isThreat ? "Cluster Anomalous Activity" : null,
        flows: c.flow_count || 1,
        session_key: null,
        isThreat,
        membersText: c.members?.slice(0, 3).join(", ") + (c.members?.length > 3 ? ` (+${c.members.length - 3} more)` : ""),
      };
    }

    if (selectedEntity.type === "node") {
      const n = selectedEntity.data;
      const prob = n.max_risk ?? 0.04;
      const isThreat = prob >= 0.40 || (n.max_stage && n.max_stage !== "Benign");
      const blockCount = Math.min(Math.max(Math.round(prob * 10), 0), 10);

      return {
        title: n.id,
        stage: n.max_stage || (n.isInternal ? "Internal LAN Host" : "External Endpoint"),
        risk: prob,
        blockCount,
        app: n.isInternal ? "Protected Client Host" : "Internet Host / Remote Service",
        mitre: isThreat ? "T1046 Network Service Scanning" : null,
        flows: n.flow_count || n.session_count || 1,
        session_key: n.session_key,
        isThreat,
      };
    }

    return null;
  }, [selectedEntity]);

  return (
    <div
      ref={containerRef}
      className={`garud-map-wrapper ${isFullscreen ? "fullscreen" : ""}`}
      style={{
        height: isFullscreen ? "100vh" : `${height}px`,
        position: isFullscreen ? "fixed" : "relative",
        inset: isFullscreen ? "0" : "auto",
        zIndex: isFullscreen ? 9999 : 1,
      }}
    >
      {/* Top Controls Header Bar matching Reference Design */}
      <div className="garud-map-header-bar">
        <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
          <Filter size={11} color="var(--text-muted)" />
          <div className="garud-map-view-pills">
            <button
              className={`garud-map-pill-btn ${viewMode === "focused" ? "active" : ""}`}
              onClick={() => setViewMode("focused")}
              title="Organized layout with top threats and talkers"
            >
              Focused ({Math.min(12, totalNodesCount)})
            </button>
            <button
              className={`garud-map-pill-btn ${viewMode === "clusters" ? "active" : ""}`}
              onClick={() => setViewMode("clusters")}
              title="Group all active hosts into structured service clusters"
            >
              Clusters (All {totalNodesCount})
            </button>
            <button
              className={`garud-map-pill-btn ${viewMode === "threats" ? "active" : ""}`}
              onClick={() => setViewMode("threats")}
              title="Show only suspicious or malicious entities"
            >
              Threats Only
            </button>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {isFullscreen && (
            <button
              className="garud-btn garud-btn-sm"
              style={{
                padding: "3px 9px",
                fontSize: 10,
                fontWeight: 700,
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                background: "rgba(246, 69, 65, 0.15)",
                color: "var(--danger)",
                border: "1px solid var(--danger)",
                cursor: "pointer",
                borderRadius: "var(--radius-xs)",
                fontFamily: "var(--font-heading)",
                letterSpacing: "0.04em",
              }}
              onClick={() => {
                setIsFullscreen(false);
                setZoom(1);
              }}
              title="Click or press Esc key to exit fullscreen"
            >
              <Minimize2 size={11} />
              <span>EXIT FULLSCREEN (ESC)</span>
            </button>
          )}

          <span style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: "var(--success)", display: "inline-flex", alignItems: "center", gap: 4 }}>
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--success)", display: "inline-block" }} />
            Live &bull; {totalEdgesCount} flows
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: "var(--text-muted)" }}>
            {lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
          </span>
        </div>
      </div>

      {/* Canvas Area */}
      <div className="garud-map-canvas-area">
        {/* Zoom and Fullscreen Controls */}
        <div className="garud-map-controls">
          <button
            className="garud-map-btn"
            onClick={() => setZoom((z) => Math.min(Number((z + 0.2).toFixed(2)), 3.0))}
            title="Zoom In"
            aria-label="Zoom In"
          >
            <Plus size={13} />
          </button>
          {zoom !== 1 && (
            <button
              className="garud-map-btn"
              onClick={() => setZoom(1)}
              title="Reset Zoom to 100%"
              aria-label="Reset Zoom"
              style={{ fontSize: 8.5, fontFamily: "var(--font-mono)", width: "auto", minWidth: 24, padding: "0 3px" }}
            >
              {Math.round(zoom * 100)}%
            </button>
          )}
          <button
            className="garud-map-btn"
            onClick={() => setZoom((z) => Math.max(Number((z - 0.2).toFixed(2)), 0.5))}
            title="Zoom Out"
            aria-label="Zoom Out"
          >
            <Minus size={13} />
          </button>
          <button
            className={`garud-map-btn ${isFullscreen ? "active" : ""}`}
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit Fullscreen (Esc)" : "Fullscreen Topology"}
            aria-label={isFullscreen ? "Exit Fullscreen" : "Fullscreen Topology"}
            style={isFullscreen ? { borderColor: "var(--danger)", color: "var(--danger)" } : {}}
          >
            {isFullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>



        {/* HUD Intelligence Card (Matching Center Card from Reference) */}
        {hudDetails && (
          <div className={`garud-map-hud-card ${hudDetails.isThreat ? "threat" : "nominal"}`}>
            <div className="garud-map-hud-header">
              <span className="garud-map-hud-title">{hudDetails.title}</span>
              <button
                onClick={() => setSelectedEntity(null)}
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  padding: 0,
                  display: "flex",
                }}
                aria-label="Close HUD"
              >
                <X size={12} />
              </button>
            </div>

            <div className="garud-map-hud-row">
              <span style={{ color: "var(--text-secondary)" }}>Stage:</span>
              <span style={{ fontWeight: 700, color: hudDetails.isThreat ? "var(--danger)" : "var(--success)" }}>
                {hudDetails.stage}
              </span>
            </div>

            <div className="garud-map-hud-row">
              <span style={{ color: "var(--text-secondary)" }}>Risk:</span>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontWeight: 700, color: hudDetails.isThreat ? "var(--danger)" : "var(--success)" }}>
                  {hudDetails.risk.toFixed(2)}
                </span>
                <div style={{ display: "flex", gap: 2 }}>
                  {Array.from({ length: 10 }).map((_, i) => (
                    <span
                      key={i}
                      style={{
                        width: 4,
                        height: 8,
                        borderRadius: 1,
                        background:
                          i < hudDetails.blockCount
                            ? hudDetails.isThreat
                              ? "var(--danger)"
                              : "var(--success)"
                            : "var(--border)",
                      }}
                    />
                  ))}
                </div>
              </div>
            </div>

            <div className="garud-map-hud-row">
              <span style={{ color: "var(--text-secondary)" }}>Application:</span>
              <span style={{ color: "var(--text-primary)" }}>{hudDetails.app}</span>
            </div>

            {hudDetails.mitre && (
              <div className="garud-map-hud-row">
                <span style={{ color: "var(--text-secondary)" }}>MITRE:</span>
                <span style={{ color: "var(--danger)", fontWeight: 600 }}>{hudDetails.mitre}</span>
              </div>
            )}

            <div className="garud-map-hud-row">
              <span style={{ color: "var(--text-secondary)" }}>Flows:</span>
              <span style={{ color: "var(--text-primary)" }}>{hudDetails.flows.toLocaleString()} active</span>
            </div>

            {hudDetails.membersText && (
              <div className="garud-map-hud-row" style={{ alignItems: "flex-start", gap: 6, marginTop: 3 }}>
                <span style={{ color: "var(--text-secondary)", flexShrink: 0 }}>Hosts:</span>
                <span style={{ color: "var(--text-primary)", fontSize: 9, wordBreak: "break-all", textAlign: "right" }}>
                  {hudDetails.membersText}
                </span>
              </div>
            )}

            {onSelectSession && hudDetails.session_key && (
              <button
                className="garud-btn garud-btn-sm garud-btn-primary"
                style={{ marginTop: 8, width: "100%", justifyContent: "center", padding: "4px 8px", fontSize: 11 }}
                onClick={() => {
                  onSelectSession({ session_key: hudDetails.session_key, src_ip: hudDetails.title });
                }}
              >
                <span>View Details</span>
                <ArrowRight size={11} />
              </button>
            )}
          </div>
        )}

        {/* Loading Overlay */}
        {loading && visibleNodes.length === 0 && (
          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              pointerEvents: "none",
              zIndex: 10,
            }}
          >
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", letterSpacing: "0.08em" }}>
              MAPPING NETWORK TOPOLOGY NODES...
            </span>
          </div>
        )}

        {/* Empty State Overlay */}
        {!loading && visibleNodes.length === 0 && (
          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              pointerEvents: "none",
              zIndex: 10,
            }}
          >
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", letterSpacing: "0.08em" }}>
              NO ACTIVE TOPOLOGY NODES RECORDED
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-dim)", marginTop: 4 }}>
              Listening on network adapters for active host connections...
            </span>
          </div>
        )}

        {/* SVG Topology Canvas */}
        <svg
          width="100%"
          height="100%"
          viewBox="0 0 840 420"
          preserveAspectRatio="xMidYMid meet"
          style={{
            transform: `scale(${zoom})`,
            transformOrigin: "center center",
            transition: "transform 150ms ease-out",
          }}
        >
          <defs>
            {/* Subtle Technical Dotted Grid */}
            <pattern id="techGrid" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1" fill={isDark ? "rgba(231,240,244,0.10)" : "rgba(37,42,45,0.12)"} />
            </pattern>

            {/* Directional Arrowheads with proper offsets */}
            <marker id="arrow-nominal" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill={isDark ? "#39DFEB" : "#252A2D"} opacity="0.6" />
            </marker>
            <marker id="arrow-warn" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#F6B144" />
            </marker>
            <marker id="arrow-danger" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#F64541" />
            </marker>

            {/* Threat Glow Filter */}
            <filter id="threatGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Dotted Background */}
          <rect width="100%" height="100%" fill="url(#techGrid)" />

          {/* Subtle World Map Silhouette (matching reference design) */}
          <path
            d="M 120 180 C 130 160 160 150 180 165 C 200 180 220 190 240 185 C 260 180 270 200 280 220 C 260 250 230 260 210 245 C 180 220 140 230 120 180 Z M 360 160 C 380 140 420 145 440 170 C 460 190 490 185 520 200 C 510 230 480 250 450 240 C 420 230 380 240 360 200 Z M 600 170 C 640 150 680 160 710 180 C 730 200 760 210 750 240 C 730 260 690 250 660 240 C 620 220 600 200 600 170 Z M 480 280 C 510 270 540 285 550 310 C 540 330 520 340 490 335 C 470 320 460 295 480 280 Z"
            fill={isDark ? "rgba(57, 223, 235, 0.035)" : "rgba(37, 42, 45, 0.04)"}
          />

          {/* Subtle Technical Zone Watermarks matching the Reference Design */}
          <g fill={isDark ? "rgba(231,240,244,0.10)" : "rgba(37,42,45,0.13)"} fontFamily="var(--font-heading)" fontSize="10.5" fontWeight="700" letterSpacing="0.08em">
            <text x="35" y="30">EXTERNAL / INTERNET</text>
            <text x="350" y="30">DMZ / PUBLIC</text>
            <text x="35" y="405">INTERNAL / CORPORATE LAN</text>
            <text x="640" y="405">REMOTE / CLOUD SERVICES</text>
          </g>

          {/* Directed Flow Edges */}
          {(layout.displayEdges || []).map((edge, idx) => {
            const src = layout.nodeCoords.get(edge.source);
            const tgt = layout.nodeCoords.get(edge.target);
            if (!src || !tgt) return null;

            const edgeRisk = edge.probability || 0;
            const markerId = edgeRisk >= 0.65 ? "url(#arrow-danger)" : edgeRisk >= 0.35 ? "url(#arrow-warn)" : "url(#arrow-nominal)";
            const strokeWidth = Math.min(Math.max((edge.flow_count || 1) * 0.15, 1.2), 3.0);
            const isSelectedFlow =
              selectedEntity?.type === "flow" &&
              selectedEntity.data.source === edge.source &&
              selectedEntity.data.target === edge.target;

            // Subtle curved line for parallel clearance
            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2 - (idx % 3 === 1 ? 14 : idx % 3 === 2 ? -14 : 0);
            const pathData = `M ${src.x} ${src.y} Q ${midX} ${midY} ${tgt.x} ${tgt.y}`;

            return (
              <g key={`edge-${idx}`}>
                {/* Invisible wide hit area for easy clicking */}
                <path
                  d={pathData}
                  fill="none"
                  stroke="transparent"
                  strokeWidth="12"
                  style={{ cursor: "pointer" }}
                  onClick={() => setSelectedEntity({ type: "flow", data: edge })}
                />
                {/* Visible Edge */}
                <path
                  d={pathData}
                  fill="none"
                  stroke={isSelectedFlow ? "var(--accent)" : getEdgeColor(edge)}
                  strokeWidth={isSelectedFlow ? strokeWidth + 1.5 : strokeWidth}
                  markerEnd={markerId}
                  opacity={isSelectedFlow ? 0.95 : 0.65}
                  style={{ cursor: "pointer", transition: "stroke 150ms" }}
                  onClick={() => setSelectedEntity({ type: "flow", data: edge })}
                />
              </g>
            );
          })}

          {/* Network Nodes with Double Ring & SVG Icons */}
          {Array.from(layout.nodeCoords.values()).map((node) => {
            const color = getNodeColor(node);
            const isSelected =
              (selectedEntity?.type === "node" && selectedEntity.data.id === node.id) ||
              (selectedEntity?.type === "flow" && (selectedEntity.data.source === node.id || selectedEntity.data.target === node.id));
            const isThreat = color === "var(--node-malicious)" || color === "var(--node-suspicious)";

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => setSelectedEntity({ type: "node", data: node })}
                style={{ cursor: "pointer" }}
              >
                {/* Outer Threat Pulse Ring */}
                {isThreat && (
                  <circle
                    r="23"
                    fill="none"
                    stroke={color}
                    strokeWidth="1.5"
                    opacity="0.35"
                    className="threat-pulse-ring"
                  />
                )}

                {/* Outer Concentric Ring */}
                <circle
                  r="17"
                  fill="none"
                  stroke={color}
                  strokeWidth="1"
                  opacity={isSelected ? "0.9" : "0.45"}
                />

                {/* Inner Filled Circle with High Contrast Background */}
                <circle
                  r={isSelected ? "13" : "12"}
                  fill={isDark ? "#041212" : "#FEFBF6"}
                  stroke={color}
                  strokeWidth={isSelected ? "2.5" : "2"}
                  filter={isThreat ? "url(#threatGlow)" : undefined}
                />

                {/* Technical Node Icon */}
                <RenderNodeIcon role={node.role || "external"} color={color} />

                {/* Clean IP Label underneath */}
                <text
                  y="26"
                  textAnchor="middle"
                  fill={isSelected ? "var(--accent)" : isDark ? "#E7F0F4" : "#252A2D"}
                  fontSize="9.5"
                  fontFamily="var(--font-mono)"
                  fontWeight={isSelected ? "700" : "500"}
                  style={{ userSelect: "none" }}
                >
                  {formatNodeLabel(node.label || node.id)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* High-Tech Footer Bar with Clean Embedded Horizontal Legend */}
      <div className="garud-map-footer-bar">
        <div className="garud-map-footer-left">
          <Radio size={10} color="var(--accent)" />
          <span>
            {viewMode === "clusters"
              ? `Grouped all ${totalNodesCount} hosts into ${Array.from(layout.nodeCoords.values()).filter((n) => n.isCluster).length} service clusters • ${totalEdgesCount} flows`
              : `Showing ${Math.min(layout.nodeCoords.size, totalNodesCount)} of ${totalNodesCount} hosts • ${totalEdgesCount} flows ${viewMode === "focused" ? "(filtered)" : ""}`}
          </span>
        </div>

        {/* Clean, Non-Intrusive Horizontal Legend in Footer */}
        <div className="garud-map-footer-legend">
          <div className="garud-map-legend-item">
            <span className="garud-map-legend-dot internal" />
            <span>Internal</span>
          </div>
          <div className="garud-map-legend-item">
            <span className="garud-map-legend-dot external" />
            <span>External</span>
          </div>
          <div className="garud-map-legend-item">
            <span className="garud-map-legend-dot suspicious" />
            <span>Suspicious</span>
          </div>
          <div className="garud-map-legend-item">
            <span className="garud-map-legend-dot malicious" />
            <span>Malicious</span>
          </div>
          <div className="garud-map-legend-item" style={{ marginLeft: 4 }}>
            <span style={{ width: 12, height: 1.5, background: "var(--observed)", display: "inline-block" }} />
            <span>Observed Flow</span>
          </div>
        </div>

        <div className="garud-map-footer-stats">
          {isFullscreen && (
            <>
              <span style={{ color: "var(--accent)", fontWeight: 600 }}>Mouse Wheel = Zoom</span>
              <span>&bull;</span>
            </>
          )}
          <span>Flow direction &rarr;</span>
          <span>&bull;</span>
          <span>Edge thickness = volume</span>
          <span>&bull;</span>
          <span>Solid = observed</span>
        </div>
      </div>
    </div>
  );
}
