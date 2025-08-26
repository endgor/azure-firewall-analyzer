import React, { useCallback, useMemo, useState, useRef } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  ConnectionLineType,
  MarkerType
} from 'reactflow';
import type { Node, Edge } from 'reactflow';
import 'reactflow/dist/style.css';
import type { 
  ProcessedRuleCollectionGroup, 
  ProcessedRule 
} from '../../types/firewall.types';

interface RuleMindMapProps {
  groups: ProcessedRuleCollectionGroup[];
  policyName: string;
  onRuleSelect?: (rule: ProcessedRule) => void;
  selectedRuleId?: string;
}

interface CustomNodeData {
  label: string;
  type: 'policy' | 'group' | 'collection' | 'rule';
  rule?: ProcessedRule;
  priority?: number;
  ruleCategory?: string;
  ruleCount?: number;
}

const nodeTypes = {
  // We'll use default nodes with custom styling
};

export const RuleMindMap: React.FC<RuleMindMapProps> = ({ groups, policyName, onRuleSelect, selectedRuleId }) => {
  const reactFlowInstance = useRef<any>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [collapsedCollections, setCollapsedCollections] = useState<Set<string>>(new Set());
  const [showControls, setShowControls] = useState<boolean>(true);
  const [originalNodes, setOriginalNodes] = useState<Node<CustomNodeData>[]>([]);
  const [reactFlowKey, setReactFlowKey] = useState<number>(0);

  const toggleGroup = useCallback((groupId: string) => {
    setCollapsedGroups(prev => {
      const newSet = new Set(prev);
      if (newSet.has(groupId)) {
        newSet.delete(groupId);
      } else {
        newSet.add(groupId);
      }
      return newSet;
    });
    setReactFlowKey(prev => prev + 1); // Force re-render
  }, []);

  const toggleCollection = useCallback((collectionId: string) => {
    setCollapsedCollections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(collectionId)) {
        newSet.delete(collectionId);
      } else {
        newSet.add(collectionId);
      }
      return newSet;
    });
    setReactFlowKey(prev => prev + 1); // Force re-render
  }, []);

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const nodes: Node<CustomNodeData>[] = [];
    const edges: Edge[] = [];

    // Calculate layout dimensions
    const sortedGroups = [...groups].sort((a, b) => a.priority - b.priority);
    const totalGroups = sortedGroups.length;
    
    // Use hierarchical layout instead of circular
    const startY = 100;
    // Dynamic group width based on collapsed state - tighter spacing when collapsed
    const allGroupsCollapsed = sortedGroups.every(g => collapsedGroups.has(`group-${g.id}`));
    const groupWidth = allGroupsCollapsed ? 200 : 300;
    
    // Central policy node at top
    const policyNode: Node<CustomNodeData> = {
      id: 'policy',
      type: 'default',
      data: {
        label: policyName,
        type: 'policy',
      },
      position: { x: groupWidth * Math.max(3, totalGroups) / 2 - 100, y: startY },
      style: {
        background: '#1e40af',
        color: '#ffffff',
        border: '3px solid #1e40af',
        borderRadius: '12px',
        fontSize: '16px',
        fontWeight: 'bold',
        padding: '16px 20px',
        width: 200,
        textAlign: 'center',
        minHeight: '60px'
      }
    };
    nodes.push(policyNode);

    // Position groups horizontally across the screen
    sortedGroups.forEach((group, groupIndex) => {
      const groupId = `group-${group.id}`;
      const isCollapsed = collapsedGroups.has(groupId);
      
      // Calculate horizontal position for groups
      const groupX = (groupIndex + 1) * groupWidth;
      const groupY = startY + 150;

      const totalRules = group.processedCollections.reduce((sum, col) => sum + col.processedRules.length, 0);
      
      const groupNode: Node<CustomNodeData> = {
        id: groupId,
        type: 'default',
        data: {
          label: `${isCollapsed ? '▶' : '▼'} ${group.name}\nPriority: ${group.priority}\n${totalRules} rules`,
          type: 'group',
          priority: group.priority,
          ruleCount: totalRules
        },
        position: { x: groupX - 100, y: groupY },
        style: {
          background: group.isParentPolicy ? '#7c3aed' : '#059669',
          color: '#ffffff',
          border: '3px solid #374151',
          borderRadius: '10px',
          fontSize: '13px',
          padding: '12px 16px',
          width: 180,
          textAlign: 'center',
          whiteSpace: 'pre-line',
          cursor: 'pointer',
          minHeight: '80px'
        }
      };
      nodes.push(groupNode);

      // Edge from policy to group
      edges.push({
        id: `policy-${groupId}`,
        source: 'policy',
        target: groupId,
        type: 'smoothstep',
        animated: false,
        style: { stroke: '#6b7280', strokeWidth: 3 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#6b7280',
        },
      });

      // Skip collections if group is collapsed
      if (isCollapsed) {
        return;
      }

      // Add collections vertically below each group
      const sortedCollections = [...group.processedCollections].sort((a, b) => {
        // Sort by category first (DNAT -> Network -> Application), then by priority
        const categoryOrder = { 'DNAT': 0, 'Network': 1, 'Application': 2 };
        const aCategoryOrder = categoryOrder[a.ruleCategory as keyof typeof categoryOrder] ?? 3;
        const bCategoryOrder = categoryOrder[b.ruleCategory as keyof typeof categoryOrder] ?? 3;
        
        if (aCategoryOrder !== bCategoryOrder) {
          return aCategoryOrder - bCategoryOrder;
        }
        return a.priority - b.priority;
      });

      sortedCollections.forEach((collection, collectionIndex) => {
        const collectionId = `collection-${collection.id}`;
        const isCollectionCollapsed = collapsedCollections.has(collectionId);
        
        // Position collections vertically below the group with spacing
        const collectionX = groupX;
        const collectionY = groupY + 120 + (collectionIndex * 140);

        const categoryColors = {
          DNAT: { bg: '#dbeafe', border: '#3b82f6', text: '#1e40af' },
          Network: { bg: '#dcfce7', border: '#10b981', text: '#059669' },
          Application: { bg: '#fef3c7', border: '#f59e0b', text: '#d97706' }
        };

        const colors = categoryColors[collection.ruleCategory as keyof typeof categoryColors] || categoryColors.Application;

        const collectionNode: Node<CustomNodeData> = {
          id: collectionId,
          type: 'default',
          data: {
            label: `${isCollectionCollapsed ? '▶' : '▼'} ${collection.name}\n${collection.ruleCategory} (P:${collection.priority})\n${collection.processedRules.length} rules`,
            type: 'collection',
            priority: collection.priority,
            ruleCategory: collection.ruleCategory,
            ruleCount: collection.processedRules.length
          },
          position: { x: collectionX - 90, y: collectionY },
          style: {
            background: colors.bg,
            color: colors.text,
            border: `2px solid ${colors.border}`,
            borderRadius: '8px',
            fontSize: '11px',
            padding: '8px 12px',
            width: 160,
            textAlign: 'center',
            whiteSpace: 'pre-line',
            cursor: 'pointer',
            minHeight: '60px'
          }
        };
        nodes.push(collectionNode);

        // Edge from group to collection
        edges.push({
          id: `${groupId}-${collectionId}`,
          source: groupId,
          target: collectionId,
          type: 'smoothstep',
          animated: false,
          style: { stroke: colors.border, strokeWidth: 2 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: colors.border,
          },
        });

        // Skip rules if collection is collapsed
        if (isCollectionCollapsed) {
          return;
        }

        // Add rules horizontally to the right of each collection
        const rulesPerRow = Math.min(5, collection.processedRules.length); // Max 5 rules per row
        const ruleSpacing = 120;
        const ruleRowHeight = 80;

        collection.processedRules.forEach((rule, ruleIndex) => {
          const ruleId = `rule-${rule.id}`;
          
          // Calculate position in grid
          const row = Math.floor(ruleIndex / rulesPerRow);
          const col = ruleIndex % rulesPerRow;
          
          const ruleX = collectionX + 200 + (col * ruleSpacing);
          const ruleY = collectionY - 30 + (row * ruleRowHeight);

          const ruleNode: Node<CustomNodeData> = {
            id: ruleId,
            type: 'default',
            data: {
              label: `${rule.name}\n#${rule.processingOrder}`,
              type: 'rule',
              rule: rule,
              priority: rule.processingOrder
            },
            position: { x: ruleX - 50, y: ruleY },
            style: {
              background: rule.id === selectedRuleId ? '#fbbf24' : colors.bg,
              color: colors.text,
              border: `1px solid ${colors.border}`,
              borderRadius: '6px',
              fontSize: '9px',
              padding: '6px 8px',
              width: 100,
              textAlign: 'center',
              whiteSpace: 'pre-line',
              cursor: 'pointer',
              minHeight: '40px'
            }
          };
          nodes.push(ruleNode);

          // Edge from collection to rule
          edges.push({
            id: `${collectionId}-${ruleId}`,
            source: collectionId,
            target: ruleId,
            type: 'straight',
            animated: false,
            style: { stroke: colors.border, strokeWidth: 1 },
          });
        });
      });
    });

    return { nodes, edges };
  }, [groups, policyName, selectedRuleId, collapsedGroups, collapsedCollections]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Update nodes when initial nodes change (due to collapse state changes)
  React.useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  // Update edges when initial edges change
  React.useEffect(() => {
    setEdges(initialEdges);
  }, [initialEdges, setEdges]);

  // Store original positions when nodes are first created
  React.useEffect(() => {
    if (initialNodes.length > 0 && originalNodes.length === 0) {
      setOriginalNodes(initialNodes.map(node => ({ ...node })));
    }
  }, [initialNodes, originalNodes.length]);

  const onConnect = useCallback(
    (params: any) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node<CustomNodeData>) => {
    if (node.data.type === 'rule' && node.data.rule) {
      onRuleSelect?.(node.data.rule);
    } else if (node.data.type === 'group') {
      toggleGroup(node.id);
    } else if (node.data.type === 'collection') {
      toggleCollection(node.id);
    }
  }, [onRuleSelect, toggleGroup, toggleCollection]);

  const expandAll = useCallback(() => {
    setCollapsedGroups(new Set());
    setCollapsedCollections(new Set());
    setReactFlowKey(prev => prev + 1); // Force re-render
    // Fit view after expanding to show all nodes
    setTimeout(() => {
      if (reactFlowInstance.current) {
        reactFlowInstance.current.fitView({ padding: 0.1 });
      }
    }, 200);
  }, []);

  const collapseAll = useCallback(() => {
    const allGroupIds = groups.map(g => `group-${g.id}`);
    const allCollectionIds = groups.flatMap(g => 
      g.processedCollections.map(c => `collection-${c.id}`)
    );
    setCollapsedGroups(new Set(allGroupIds));
    setCollapsedCollections(new Set(allCollectionIds));
    setReactFlowKey(prev => prev + 1); // Force re-render
    // Fit view after collapsing to show the grouped layout
    setTimeout(() => {
      if (reactFlowInstance.current) {
        reactFlowInstance.current.fitView({ padding: 0.2 });
      }
    }, 200);
  }, [groups]);

  const resetView = useCallback(() => {
    // Reset all collapse states to initial (nothing collapsed)
    setCollapsedGroups(new Set());
    setCollapsedCollections(new Set());
    setReactFlowKey(prev => prev + 1); // Force complete re-render
    
    // Reset to original node positions if available
    setTimeout(() => {
      if (reactFlowInstance.current) {
        // Reset zoom and position to initial state
        reactFlowInstance.current.setViewport({ x: 0, y: 0, zoom: 1 });
        
        // Force a re-render by updating nodes to their recalculated positions
        // This will be triggered by the useMemo when collapse states reset
        setTimeout(() => {
          reactFlowInstance.current.fitView({ padding: 0.1 });
        }, 100);
      }
    }, 100);
  }, []);

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 h-[800px] relative">
      {/* Control Panel */}
      <div className="absolute top-4 left-4 z-10 bg-white/90 backdrop-blur-sm rounded-lg shadow-sm border">
        {showControls ? (
          <div className="p-3 space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-xs font-medium text-gray-700">Mind Map Controls</div>
              <button
                onClick={() => setShowControls(false)}
                className="p-1 hover:bg-gray-100 rounded transition-colors"
                title="Hide Controls"
              >
                <svg className="w-3 h-3 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="flex gap-2 flex-wrap">
              <button
                onClick={expandAll}
                className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors"
              >
                Expand All
              </button>
              <button
                onClick={collapseAll}
                className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
              >
                Collapse All
              </button>
              <button
                onClick={resetView}
                className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded hover:bg-green-200 transition-colors"
              >
                Reset View
              </button>
            </div>
            <div className="text-xs text-gray-500">
              Click nodes to expand/collapse
            </div>
          </div>
        ) : (
          <button
            onClick={() => setShowControls(true)}
            className="p-2 hover:bg-white/95 transition-colors"
            title="Show Controls"
          >
            <svg className="w-4 h-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            </svg>
          </button>
        )}
      </div>

      <ReactFlow
        key={reactFlowKey}
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={onNodeClick}
        onInit={(instance) => (reactFlowInstance.current = instance)}
        nodeTypes={nodeTypes}
        connectionLineType={ConnectionLineType.SmoothStep}
        defaultEdgeOptions={{
          animated: false,
          style: { strokeWidth: 1, stroke: '#6b7280' },
        }}
        fitView
        attributionPosition="bottom-left"
      >
        <Controls />
        <MiniMap
          nodeStrokeColor="#374151"
          nodeColor="#e5e7eb"
          maskColor="#f3f4f690"
        />
        <Background />
      </ReactFlow>
    </div>
  );
};

