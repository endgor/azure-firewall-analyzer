import type { ProcessedRule } from '../types/firewall.types';

interface DraftRuleData {
  ruleCollectionGroups: {
    name: string;
    priority: number;
    ruleCollections: {
      name: string;
      priority: number;
      ruleCollectionType: string;
      action?: {
        type: string;
      };
      rules: any[];
    }[];
  }[];
}

/**
 * Export modified rules to Azure Firewall Policy draft JSON format
 */
export function exportToDraftJSON(rules: ProcessedRule[]): DraftRuleData {
  const groupedRules = new Map<string, {
    groupName: string;
    groupPriority: number;
    collections: Map<string, {
      collectionName: string;
      collectionPriority: number;
      ruleType: string;
      rules: ProcessedRule[];
    }>;
  }>();

  // Group rules by collection group and collection
  rules.forEach(rule => {
    const groupName = rule.collectionGroupName || 'DefaultRuleCollectionGroup';
    const groupPriority = rule.groupPriority || 100;
    const collectionName = rule.collectionName || 'DefaultRuleCollection';
    const collectionPriority = rule.collectionPriority || 100;
    
    const groupKey = `${groupName}-${groupPriority}`;
    
    if (!groupedRules.has(groupKey)) {
      groupedRules.set(groupKey, {
        groupName: groupName,
        groupPriority: groupPriority,
        collections: new Map()
      });
    }

    const group = groupedRules.get(groupKey)!;
    const collectionKey = `${collectionName}-${collectionPriority}`;
    
    if (!group.collections.has(collectionKey)) {
      group.collections.set(collectionKey, {
        collectionName: collectionName,
        collectionPriority: collectionPriority,
        ruleType: rule.ruleType,
        rules: []
      });
    }
    
    group.collections.get(collectionKey)!.rules.push(rule);
  });

  // Convert to Azure Firewall Policy format
  const ruleCollectionGroups = Array.from(groupedRules.values()).map(group => ({
    name: group.groupName,
    priority: group.groupPriority,
    ruleCollections: Array.from(group.collections.values()).map(collection => {
      const ruleCollectionType = getRuleCollectionType(collection.ruleType);
      const action = ruleCollectionType !== 'FirewallPolicyNatRuleCollection' 
        ? { type: getActionType(collection.rules[0]) }
        : undefined;

      return {
        name: collection.collectionName,
        priority: collection.collectionPriority,
        ruleCollectionType,
        action,
        rules: collection.rules.map(rule => convertRuleToAzureFormat(rule))
      };
    })
  }));

  return { ruleCollectionGroups };
}

/**
 * Generate Azure CLI commands for creating and deploying draft policy
 */
export function generateAzureCLICommands(
  rules: ProcessedRule[], 
  policyName: string, 
  resourceGroup: string,
  subscriptionId?: string
): string {
  const commands: string[] = [];
  
  // Add subscription setting if provided
  if (subscriptionId) {
    commands.push(`# Set subscription`);
    commands.push(`az account set --subscription "${subscriptionId}"`);
    commands.push('');
  }

  commands.push(`# Azure Firewall Policy Draft Commands`);
  commands.push(`# Generated from Azure Firewall Analyzer`);
  commands.push('');

  // Create draft
  commands.push(`# 1. Create draft policy`);
  commands.push(`az network firewall policy draft create \\`);
  commands.push(`  --policy-name "${policyName}" \\`);
  commands.push(`  --resource-group "${resourceGroup}"`);
  commands.push('');

  // Group rules by collection
  const groupedRules = new Map<string, ProcessedRule[]>();
  rules.forEach(rule => {
    const groupName = rule.collectionGroupName || 'DefaultRuleCollectionGroup';
    const collectionName = rule.collectionName || 'DefaultRuleCollection';
    const key = `${groupName}/${collectionName}`;
    if (!groupedRules.has(key)) {
      groupedRules.set(key, []);
    }
    groupedRules.get(key)!.push(rule);
  });

  let commandIndex = 2;

  // Generate commands for each collection
  Array.from(groupedRules.entries()).forEach(([collectionPath, collectionRules]) => {
    const [groupName, collectionName] = collectionPath.split('/');
    
    commands.push(`# ${commandIndex}. Update rules in collection "${collectionName}"`);
    
    collectionRules.forEach((rule) => {
      commands.push(`az network firewall policy rule-collection-group draft collection rule update \\`);
      commands.push(`  --policy-name "${policyName}" \\`);
      commands.push(`  --resource-group "${resourceGroup}" \\`);
      commands.push(`  --rule-collection-group-name "${groupName}" \\`);
      commands.push(`  --collection-name "${collectionName}" \\`);
      commands.push(`  --name "${rule.name}" \\`);
      
      if (rule.ruleType === 'ApplicationRule') {
        commands.push(`  --rule-type ApplicationRule \\`);
        if (rule.targetFqdns && rule.targetFqdns.length > 0) {
          commands.push(`  --target-fqdns ${rule.targetFqdns.map(f => `"${f}"`).join(' ')} \\`);
        }
        if (rule.protocols && rule.protocols.length > 0) {
          const protocolStrs = rule.protocols.map((p: any) => `${p.protocolType}=${p.port}`);
          commands.push(`  --protocols ${protocolStrs.join(' ')} \\`);
        }
      } else if (rule.ruleType === 'NetworkRule') {
        commands.push(`  --rule-type NetworkRule \\`);
        if (rule.destinationAddresses && rule.destinationAddresses.length > 0) {
          commands.push(`  --destination-addresses ${rule.destinationAddresses.map(a => `"${a}"`).join(' ')} \\`);
        }
        if (rule.destinationFqdns && rule.destinationFqdns.length > 0) {
          commands.push(`  --destination-fqdns ${rule.destinationFqdns.map(f => `"${f}"`).join(' ')} \\`);
        }
        if (rule.destinationIpGroups && rule.destinationIpGroups.length > 0) {
          commands.push(`  --destination-ip-groups ${rule.destinationIpGroups.map(g => `"${g}"`).join(' ')} \\`);
        }
        if (rule.destinationPorts && rule.destinationPorts.length > 0) {
          commands.push(`  --destination-ports ${rule.destinationPorts.map(p => `"${p}"`).join(' ')} \\`);
        }
        if (rule.ipProtocols && rule.ipProtocols.length > 0) {
          commands.push(`  --ip-protocols ${rule.ipProtocols.join(' ')} \\`);
        }
      } else if (rule.ruleType === 'NatRule') {
        commands.push(`  --rule-type NatRule \\`);
        if (rule.destinationAddresses && rule.destinationAddresses.length > 0) {
          commands.push(`  --destination-addresses ${rule.destinationAddresses.map(a => `"${a}"`).join(' ')} \\`);
        }
        if (rule.destinationPorts && rule.destinationPorts.length > 0) {
          commands.push(`  --destination-ports ${rule.destinationPorts.map(p => `"${p}"`).join(' ')} \\`);
        }
        if (rule.translatedAddress) {
          commands.push(`  --translated-address "${rule.translatedAddress}" \\`);
        }
        if (rule.translatedPort) {
          commands.push(`  --translated-port "${rule.translatedPort}" \\`);
        }
        if (rule.ipProtocols && rule.ipProtocols.length > 0) {
          commands.push(`  --ip-protocols ${rule.ipProtocols.join(' ')} \\`);
        }
      }
      
      const hasSourceAddresses = !!(rule.sourceAddresses && rule.sourceAddresses.length > 0);
      const hasSourceIpGroups = !!(rule.sourceIpGroups && rule.sourceIpGroups.length > 0);

      if (hasSourceAddresses && hasSourceIpGroups) {
        commands.push(`  --source-addresses ${rule.sourceAddresses!.map(a => `"${a}"`).join(' ')} \\`);
        commands.push(`  --source-ip-groups ${rule.sourceIpGroups!.map(g => `"${g}"`).join(' ')}`);
      } else if (hasSourceAddresses) {
        commands.push(`  --source-addresses ${rule.sourceAddresses!.map(a => `"${a}"`).join(' ')}`);
      } else if (hasSourceIpGroups) {
        commands.push(`  --source-ip-groups ${rule.sourceIpGroups!.map(g => `"${g}"`).join(' ')}`);
      } else {
        // Remove the trailing backslash from the last line
        const lastLine = commands[commands.length - 1];
        commands[commands.length - 1] = lastLine.replace(' \\', '');
      }

      commands.push('');
    });
    
    commandIndex++;
  });

  // Add deployment commands
  commands.push(`# ${commandIndex}. Review the draft (optional)`);
  commands.push(`az network firewall policy draft show \\`);
  commands.push(`  --policy-name "${policyName}" \\`);
  commands.push(`  --resource-group "${resourceGroup}"`);
  commands.push('');

  commands.push(`# ${commandIndex + 1}. Deploy the draft to apply changes`);
  commands.push(`az network firewall policy deploy \\`);
  commands.push(`  --name "${policyName}" \\`);
  commands.push(`  --resource-group "${resourceGroup}"`);
  commands.push('');

  commands.push(`# ${commandIndex + 2}. Alternative: Delete draft without deploying`);
  commands.push(`# az network firewall policy draft delete \\`);
  commands.push(`#   --policy-name "${policyName}" \\`);
  commands.push(`#   --resource-group "${resourceGroup}"`);

  return commands.join('\n');
}

function getRuleCollectionType(ruleType: string): string {
  switch (ruleType) {
    case 'NatRule':
      return 'FirewallPolicyNatRuleCollection';
    case 'NetworkRule':
      return 'FirewallPolicyFilterRuleCollection';
    case 'ApplicationRule':
      return 'FirewallPolicyFilterRuleCollection';
    default:
      return 'FirewallPolicyFilterRuleCollection';
  }
}

function getActionType(rule: ProcessedRule): string {
  // For NAT rules, action is implicit (DNAT)
  if (rule.ruleType === 'NatRule') {
    return 'DNAT';
  }
  
  // For Network and Application rules, check action property or default to Allow
  return (rule as any).action || 'Allow';
}

function convertRuleToAzureFormat(rule: ProcessedRule): any {
  const baseRule = {
    name: rule.name,
    ruleType: rule.ruleType,
    sourceAddresses: rule.sourceAddresses || [],
    sourceIpGroups: rule.sourceIpGroups || []
  };

  switch (rule.ruleType) {
    case 'ApplicationRule':
      return {
        ...baseRule,
        targetFqdns: rule.targetFqdns || [],
        fqdnTags: rule.fqdnTags || [],
        targetUrls: rule.targetUrls || [],
        protocols: rule.protocols || [],
        webCategories: rule.webCategories || []
      };

    case 'NetworkRule':
      return {
        ...baseRule,
        ipProtocols: rule.ipProtocols || [],
        destinationAddresses: rule.destinationAddresses || [],
        destinationIpGroups: rule.destinationIpGroups || [],
        destinationFqdns: rule.destinationFqdns || [],
        destinationPorts: rule.destinationPorts || []
      };

    case 'NatRule':
      return {
        ...baseRule,
        ipProtocols: rule.ipProtocols || [],
        destinationAddresses: rule.destinationAddresses || [],
        destinationPorts: rule.destinationPorts || [],
        translatedAddress: rule.translatedAddress,
        translatedPort: rule.translatedPort,
        translatedFqdn: (rule as any).translatedFqdn
      };

    default:
      return baseRule;
  }
}
