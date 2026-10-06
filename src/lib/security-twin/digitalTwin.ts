import {
  TwinNode,
  TwinEdge,
  TwinNodeType,
  IsolationSimulationResult,
} from "./types";

export class SecurityDigitalTwin {
  // Tenant-partitioned store: tenantId -> (nodeId -> TwinNode)
  private static nodes: Map<string, Map<string, TwinNode>> = new Map();
  // Tenant-partitioned edges: tenantId -> TwinEdge[]
  private static edges: Map<string, TwinEdge[]> = new Map();

  public static upsertNode(node: TwinNode): void {
    if (!this.nodes.has(node.tenantId)) {
      this.nodes.set(node.tenantId, new Map());
    }
    const tenantNodes = this.nodes.get(node.tenantId)!;
    tenantNodes.set(node.id, {
      ...node,
      updatedAt: new Date().toISOString(),
      createdAt: node.createdAt || new Date().toISOString(),
    });
  }

  public static upsertEdge(edge: TwinEdge): void {
    if (!this.edges.has(edge.tenantId)) {
      this.edges.set(edge.tenantId, []);
    }
    const tenantEdges = this.edges.get(edge.tenantId)!;
    const existingIdx = tenantEdges.findIndex((e) => e.id === edge.id);
    if (existingIdx >= 0) {
      tenantEdges[existingIdx] = edge;
    } else {
      tenantEdges.push(edge);
    }
  }

  public static getNode(tenantId: string, nodeId: string): TwinNode | undefined {
    return this.nodes.get(tenantId)?.get(nodeId);
  }

  public static getNodes(tenantId: string, type?: TwinNodeType): TwinNode[] {
    const tenantNodes = this.nodes.get(tenantId);
    if (!tenantNodes) return [];
    const all = Array.from(tenantNodes.values());
    return type ? all.filter((n) => n.type === type) : all;
  }

  public static getEdges(tenantId: string): TwinEdge[] {
    return this.edges.get(tenantId) || [];
  }

  /**
   * Question 1: What depends on this asset?
   * (Returns nodes that have an edge pointing TO this asset or depends_on this asset)
   */
  public static getDependencies(tenantId: string, assetId: string): TwinNode[] {
    const edges = this.getEdges(tenantId);
    const dependentNodeIds = new Set<string>();

    for (const edge of edges) {
      // If source depends on asset, or target is asset
      if (edge.targetId === assetId && (edge.relationType === "depends_on" || edge.relationType === "connects_to")) {
        dependentNodeIds.add(edge.sourceId);
      }
    }

    return Array.from(dependentNodeIds)
      .map((id) => this.getNode(tenantId, id))
      .filter((n): n is TwinNode => n !== undefined);
  }

  /**
   * Question 2: What can reach this asset?
   * (Returns nodes with network reachability, connects_to, or can_reach)
   */
  public static getInboundReachability(tenantId: string, assetId: string): TwinNode[] {
    const edges = this.getEdges(tenantId);
    const reachableFromIds = new Set<string>();

    for (const edge of edges) {
      if (edge.targetId === assetId && (edge.relationType === "can_reach" || edge.relationType === "connects_to")) {
        reachableFromIds.add(edge.sourceId);
      } else if (edge.bidirectional && edge.sourceId === assetId) {
        reachableFromIds.add(edge.targetId);
      }
    }

    return Array.from(reachableFromIds)
      .map((id) => this.getNode(tenantId, id))
      .filter((n): n is TwinNode => n !== undefined);
  }

  /**
   * Question 3: What vulnerabilities exist on this asset?
   */
  public static getVulnerabilities(tenantId: string, assetId: string): TwinNode[] {
    const edges = this.getEdges(tenantId);
    const vulnIds = new Set<string>();

    for (const edge of edges) {
      if (edge.sourceId === assetId && edge.relationType === "has_vulnerability") {
        vulnIds.add(edge.targetId);
      }
    }

    return Array.from(vulnIds)
      .map((id) => this.getNode(tenantId, id))
      .filter((n): n is TwinNode => n !== undefined && n.type === "vulnerability");
  }

  /**
   * Question 4: What identities can access it?
   */
  public static getAuthorizedIdentities(tenantId: string, assetId: string): TwinNode[] {
    const edges = this.getEdges(tenantId);
    const identityIds = new Set<string>();

    for (const edge of edges) {
      if (edge.targetId === assetId && (edge.relationType === "authenticates_as" || edge.relationType === "manages")) {
        identityIds.add(edge.sourceId);
      }
    }

    return Array.from(identityIds)
      .map((id) => this.getNode(tenantId, id))
      .filter((n): n is TwinNode => n !== undefined && (n.type === "identity" || n.type === "user"));
  }

  /**
   * Question 5: What business services depend on it?
   */
  public static getImpactedBusinessServices(tenantId: string, assetId: string): TwinNode[] {
    const visited = new Set<string>();
    const queue = [assetId];
    const impactedServices: TwinNode[] = [];

    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (visited.has(curr)) continue;
      visited.add(curr);

      const upstream = this.getDependencies(tenantId, curr);
      for (const node of upstream) {
        if (node.type === "business_service") {
          impactedServices.push(node);
        } else if (!visited.has(node.id)) {
          queue.push(node.id);
        }
      }
    }

    return Array.from(new Set(impactedServices.map((s) => s.id)))
      .map((id) => this.getNode(tenantId, id))
      .filter((n): n is TwinNode => n !== undefined);
  }

  /**
   * Question 6: What happens if it is isolated?
   */
  public static simulateIsolation(tenantId: string, assetId: string): IsolationSimulationResult {
    const target = this.getNode(tenantId, assetId);
    const assetName = target ? target.name : assetId;
    const edges = this.getEdges(tenantId);

    // Sever all incoming and outgoing connections
    const severed = edges.filter((e) => e.sourceId === assetId || e.targetId === assetId);

    const affectedUpstream = this.getDependencies(tenantId, assetId);
    const affectedDownstream = this.getInboundReachability(tenantId, assetId);
    const disruptedServices = this.getImpactedBusinessServices(tenantId, assetId);
    const disconnectedUsers = this.getAuthorizedIdentities(tenantId, assetId);

    // Calculate blast radius score (0 - 100)
    let score = severed.length * 5;
    score += affectedUpstream.length * 10;
    score += disruptedServices.length * 25;
    if (target?.criticality === "critical") score += 30;
    if (target?.criticality === "high") score += 15;
    score = Math.min(100, Math.max(5, score));

    let residualRisk: IsolationSimulationResult["residualRisk"] = "low";
    if (score > 75) residualRisk = "critical";
    else if (score > 50) residualRisk = "high";
    else if (score > 25) residualRisk = "medium";

    return {
      tenantId,
      isolatedAssetId: assetId,
      isolatedAssetName: assetName,
      severedEdgesCount: severed.length,
      affectedUpstreamAssets: affectedUpstream,
      affectedDownstreamAssets: affectedDownstream,
      disruptedBusinessServices: disruptedServices,
      disconnectedIdentities: disconnectedUsers,
      blastRadiusScore: score,
      residualRisk,
      summary: `Simulating isolation of '${assetName}': ${severed.length} active edges severed, ${affectedUpstream.length} dependent assets impacted, ${disruptedServices.length} business services disrupted. Blast radius score: ${score}/100.`,
    };
  }

  public static clear(tenantId?: string): void {
    if (tenantId) {
      this.nodes.delete(tenantId);
      this.edges.delete(tenantId);
    } else {
      this.nodes.clear();
      this.edges.clear();
    }
  }
}
