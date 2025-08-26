// Azure Firewall Policy Types

export type RuleType = 'ApplicationRule' | 'NetworkRule' | 'NatRule';
export type RuleCollectionType = 'FirewallPolicyFilterRuleCollection' | 'FirewallPolicyNatRuleCollection';
export type ActionType = 'Allow' | 'Deny' | 'Dnat';
export type ProtocolType = 'Http' | 'Https' | 'Mssql' | 'TCP' | 'UDP' | 'Any' | 'ICMP';
export type ThreatIntelMode = 'Off' | 'Alert' | 'Deny';
export type IdpsMode = 'Off' | 'Alert' | 'Deny';

// Individual Rule Interfaces
export interface BaseRule {
  ruleType: RuleType;
  name: string;
  description?: string;
}

export interface ApplicationRule extends BaseRule {
  ruleType: 'ApplicationRule';
  protocols: Array<{
    protocolType: ProtocolType;
    port: number;
  }>;
  fqdnTags: string[];
  webCategories: string[];
  targetFqdns: string[];
  targetUrls: string[];
  terminateTLS: boolean;
  sourceAddresses: string[];
  destinationAddresses: string[];
  sourceIpGroups: string[];
  httpHeadersToInsert: Array<{
    name: string;
    value: string;
  }>;
}

export interface NetworkRule extends BaseRule {
  ruleType: 'NetworkRule';
  ipProtocols: string[];
  sourceAddresses: string[];
  destinationAddresses: string[];
  sourceIpGroups: string[];
  destinationIpGroups: string[];
  destinationPorts: string[];
  destinationFqdns?: string[];
}

export interface NatRule extends BaseRule {
  ruleType: 'NatRule';
  translatedAddress: string;
  translatedPort: string;
  ipProtocols: string[];
  sourceAddresses: string[];
  sourceIpGroups: string[];
  destinationAddresses: string[];
  destinationPorts: string[];
}

export type FirewallRule = ApplicationRule | NetworkRule | NatRule;

// Rule Collection Interfaces
export interface BaseRuleCollection {
  ruleCollectionType: RuleCollectionType;
  name: string;
  priority: number;
  rules: FirewallRule[];
}

export interface FilterRuleCollection extends BaseRuleCollection {
  ruleCollectionType: 'FirewallPolicyFilterRuleCollection';
  action: {
    type: 'Allow' | 'Deny';
  };
}

export interface NatRuleCollection extends BaseRuleCollection {
  ruleCollectionType: 'FirewallPolicyNatRuleCollection';
  action: {
    type: 'Dnat';
  };
}

export type RuleCollection = FilterRuleCollection | NatRuleCollection;

// Rule Collection Group Interface
export interface RuleCollectionGroup {
  name: string;
  priority: number;
  ruleCollections: RuleCollection[];
}

// Firewall Policy Configuration
export interface FirewallPolicyProperties {
  sku: {
    tier: 'Basic' | 'Standard' | 'Premium';
  };
  threatIntelMode: ThreatIntelMode;
  dnsSettings?: {
    servers: string[];
    enableProxy: boolean;
  };
  snat?: {
    privateRanges: string[];
  };
  intrusionDetection?: {
    mode: IdpsMode;
    configuration?: {
      signatureOverrides: Array<{
        id: string;
        mode: 'Off' | 'Alert' | 'Deny';
      }>;
      bypassTrafficSettings: Array<{
        name: string;
        protocol: string;
        sourceAddresses: string[];
        destinationAddresses: string[];
        sourceIpGroups: string[];
        destinationIpGroups: string[];
        destinationPorts: string[];
      }>;
    };
  };
  transportSecurity?: {
    certificateAuthority: {
      name: string;
      keyVaultSecretId: string;
    };
  };
}

// Main Firewall Policy Interface
export interface FirewallPolicy {
  type: 'Microsoft.Network/firewallPolicies';
  apiVersion: string;
  name: string;
  location: string;
  tags?: Record<string, string>;
  identity?: {
    type: string;
    userAssignedIdentities: Record<string, any>;
  };
  properties: FirewallPolicyProperties;
  ruleCollectionGroups: RuleCollectionGroup[];
}

// Parsed and Processed Types
export interface ProcessedRule {
  // Base rule properties
  ruleType: RuleType;
  name: string;
  description?: string;
  
  // ApplicationRule properties
  protocols?: Array<{
    protocolType: ProtocolType;
    port: number;
  }>;
  fqdnTags?: string[];
  webCategories?: string[];
  targetFqdns?: string[];
  targetUrls?: string[];
  terminateTLS?: boolean;
  httpHeadersToInsert?: Array<{
    name: string;
    value: string;
  }>;
  
  // NetworkRule properties
  ipProtocols?: string[];
  destinationPorts?: string[];
  destinationFqdns?: string[];
  
  // NatRule properties
  translatedAddress?: string;
  translatedPort?: string;
  
  // Common properties
  sourceAddresses?: string[];
  destinationAddresses?: string[];
  sourceIpGroups?: string[];
  destinationIpGroups?: string[];
  
  // Processing metadata
  id: string;
  collectionName: string;
  collectionGroupName: string;
  processingOrder: number;
  ruleCategory: 'DNAT' | 'Network' | 'Application';
  groupPriority: number;
  collectionPriority: number;
  isParentPolicy: boolean;
}

export interface ProcessedRuleCollection {
  // Base collection properties
  ruleCollectionType: RuleCollectionType;
  name: string;
  priority: number;
  rules: FirewallRule[];
  action?: {
    type: ActionType;
  };
  
  // Processing metadata
  id: string;
  groupName: string;
  groupPriority: number;
  ruleCategory: 'DNAT' | 'Network' | 'Application';
  processedRules: ProcessedRule[];
}

export interface ProcessedRuleCollectionGroup extends RuleCollectionGroup {
  id: string;
  processedCollections: ProcessedRuleCollection[];
  isParentPolicy: boolean;
}

// Analysis Types
export interface RuleDuplicate {
  rules: ProcessedRule[];
  reason: string;
  severity: 'high' | 'medium' | 'low';
}

export interface RuleConflict {
  primaryRule: ProcessedRule;
  conflictingRule: ProcessedRule;
  conflictType: 'shadowing' | 'overlap' | 'contradiction';
  description: string;
}

export interface RuleAnalysis {
  totalRules: number;
  rulesByType: Record<string, number>;
  duplicates: RuleDuplicate[];
  conflicts: RuleConflict[];
  overlyPermissiveRules: ProcessedRule[];
  unusedIpGroups: string[];
  optimizationSuggestions: Array<{
    type: 'combine' | 'remove' | 'reorder';
    description: string;
    affectedRules: ProcessedRule[];
  }>;
}

// UI State Types
export interface FirewallData {
  policy: FirewallPolicy | null;
  processedGroups: ProcessedRuleCollectionGroup[];
  analysis: RuleAnalysis | null;
  selectedRule: ProcessedRule | null;
  expandedGroups: Set<string>;
  expandedCollections: Set<string>;
  searchQuery: string;
  filterByType: RuleType | 'all';
  filterByAction: ActionType | 'all';
}

// Visualization Types
export interface FlowNode {
  id: string;
  type: 'policy' | 'group' | 'collection' | 'rule';
  position: { x: number; y: number };
  data: {
    label: string;
    priority?: number;
    ruleType?: RuleType;
    actionType?: ActionType;
    processingOrder?: number;
    expanded?: boolean;
  };
  style?: Record<string, any>;
}

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  type?: string;
  style?: Record<string, any>;
  label?: string;
}