import type {
  FirewallPolicy,
  RuleCollectionGroup,
  RuleCollection,
  ProcessedRule,
  ProcessedRuleCollection,
  ProcessedRuleCollectionGroup,
} from '../types/firewall.types';

/**
 * Rule processing engine that implements Azure Firewall rule processing logic
 */
export class RuleProcessor {
  /**
   * Process firewall policy according to Azure Firewall rule processing order
   * 
   * Processing order:
   * 1. Rule Collection Groups by priority (100 = highest, 65000 = lowest)
   * 2. Within each group: DNAT → Network → Application rules
   * 3. Within each rule type: Rule Collections by priority
   * 4. Rules within collections are processed in order
   */
  static processFirewallPolicy(
    policy: FirewallPolicy,
    parentPolicy?: FirewallPolicy
  ): ProcessedRuleCollectionGroup[] {
    // Combine parent and child policies if parent exists
    const allGroups: Array<{ group: RuleCollectionGroup; isParent: boolean }> = [];
    
    // Parent policy groups always take precedence
    if (parentPolicy) {
      parentPolicy.ruleCollectionGroups.forEach(group => {
        allGroups.push({ group, isParent: true });
      });
    }
    
    policy.ruleCollectionGroups.forEach(group => {
      allGroups.push({ group, isParent: false });
    });

    // Sort rule collection groups by priority (lower number = higher priority)
    // Parent policy groups are processed first regardless of priority
    allGroups.sort((a, b) => {
      if (a.isParent && !b.isParent) return -1;
      if (!a.isParent && b.isParent) return 1;
      return a.group.priority - b.group.priority;
    });

    let globalProcessingOrder = 1;
    
    return allGroups.map(({ group, isParent }) => {
      const processedGroup = this.processRuleCollectionGroup(
        group,
        isParent,
        globalProcessingOrder
      );
      
      // Update global processing order
      globalProcessingOrder = this.getMaxProcessingOrder(processedGroup) + 1;
      
      return processedGroup;
    });
  }

  /**
   * Process a single rule collection group
   */
  private static processRuleCollectionGroup(
    group: RuleCollectionGroup,
    isParentPolicy: boolean,
    startingOrder: number
  ): ProcessedRuleCollectionGroup {
    const processedCollections: ProcessedRuleCollection[] = [];
    let currentOrder = startingOrder;

    // Separate rule collections by type
    const dnatCollections: RuleCollection[] = [];
    const networkCollections: RuleCollection[] = [];
    const applicationCollections: RuleCollection[] = [];

    group.ruleCollections.forEach(collection => {
      const hasNatRules = collection.rules.some(rule => rule.ruleType === 'NatRule');
      const hasNetworkRules = collection.rules.some(rule => rule.ruleType === 'NetworkRule');
      const hasApplicationRules = collection.rules.some(rule => rule.ruleType === 'ApplicationRule');

      if (hasNatRules) {
        dnatCollections.push(collection);
      }
      if (hasNetworkRules) {
        networkCollections.push(collection);
      }
      if (hasApplicationRules) {
        applicationCollections.push(collection);
      }
    });

    // Process DNAT rules first
    const processedDnatCollections = this.processRuleCollectionsByType(
      dnatCollections,
      'DNAT',
      group.name,
      group.priority,
      isParentPolicy,
      currentOrder
    );
    processedCollections.push(...processedDnatCollections);
    currentOrder = this.getMaxProcessingOrderFromCollections(processedDnatCollections) + 1;

    // Process Network rules second
    const processedNetworkCollections = this.processRuleCollectionsByType(
      networkCollections,
      'Network',
      group.name,
      group.priority,
      isParentPolicy,
      currentOrder
    );
    processedCollections.push(...processedNetworkCollections);
    currentOrder = this.getMaxProcessingOrderFromCollections(processedNetworkCollections) + 1;

    // Process Application rules last
    const processedApplicationCollections = this.processRuleCollectionsByType(
      applicationCollections,
      'Application',
      group.name,
      group.priority,
      isParentPolicy,
      currentOrder
    );
    processedCollections.push(...processedApplicationCollections);

    return {
      id: `group_${group.name}`,
      name: group.name,
      priority: group.priority,
      ruleCollections: group.ruleCollections,
      processedCollections,
      isParentPolicy,
    };
  }

  /**
   * Process rule collections of a specific type
   */
  private static processRuleCollectionsByType(
    collections: RuleCollection[],
    ruleCategory: 'DNAT' | 'Network' | 'Application',
    groupName: string,
    groupPriority: number,
    isParentPolicy: boolean,
    startingOrder: number
  ): ProcessedRuleCollection[] {
    // Sort collections by priority within the same type
    const sortedCollections = [...collections].sort((a, b) => a.priority - b.priority);
    
    let currentOrder = startingOrder;
    
    return sortedCollections.map(collection => {
      // Filter rules by category
      const relevantRules = collection.rules.filter(rule => {
        switch (ruleCategory) {
          case 'DNAT':
            return rule.ruleType === 'NatRule';
          case 'Network':
            return rule.ruleType === 'NetworkRule';
          case 'Application':
            return rule.ruleType === 'ApplicationRule';
          default:
            return false;
        }
      });

      const processedRules: ProcessedRule[] = relevantRules.map((rule, index) => {
        const baseProcessedRule: ProcessedRule = {
          ruleType: rule.ruleType,
          name: rule.name,
          description: rule.description,
          id: `rule_${groupName}_${collection.name}_${rule.name}_${index}`,
          collectionName: collection.name,
          collectionGroupName: groupName,
          processingOrder: currentOrder++,
          ruleCategory,
          groupPriority,
          collectionPriority: collection.priority,
          isParentPolicy,
        };

        // Copy type-specific properties
        if (rule.ruleType === 'ApplicationRule') {
          const appRule = rule as any;
          baseProcessedRule.protocols = appRule.protocols;
          baseProcessedRule.fqdnTags = appRule.fqdnTags;
          baseProcessedRule.webCategories = appRule.webCategories;
          baseProcessedRule.targetFqdns = appRule.targetFqdns;
          baseProcessedRule.targetUrls = appRule.targetUrls;
          baseProcessedRule.terminateTLS = appRule.terminateTLS;
          baseProcessedRule.httpHeadersToInsert = appRule.httpHeadersToInsert;
        } else if (rule.ruleType === 'NetworkRule') {
          const netRule = rule as any;
          baseProcessedRule.ipProtocols = netRule.ipProtocols;
          baseProcessedRule.destinationPorts = netRule.destinationPorts;
          baseProcessedRule.destinationFqdns = netRule.destinationFqdns;
        } else if (rule.ruleType === 'NatRule') {
          const natRule = rule as any;
          baseProcessedRule.translatedAddress = natRule.translatedAddress;
          baseProcessedRule.translatedPort = natRule.translatedPort;
          baseProcessedRule.ipProtocols = natRule.ipProtocols;
          baseProcessedRule.destinationPorts = natRule.destinationPorts;
        }

        // Copy common properties
        baseProcessedRule.sourceAddresses = (rule as any).sourceAddresses;
        baseProcessedRule.destinationAddresses = (rule as any).destinationAddresses;
        baseProcessedRule.sourceIpGroups = (rule as any).sourceIpGroups;
        baseProcessedRule.destinationIpGroups = (rule as any).destinationIpGroups;

        return baseProcessedRule;
      });

      return {
        ...collection,
        id: `collection_${groupName}_${collection.name}`,
        groupName,
        groupPriority,
        ruleCategory,
        processedRules,
      };
    });
  }

  /**
   * Get maximum processing order from a group
   */
  private static getMaxProcessingOrder(group: ProcessedRuleCollectionGroup): number {
    let maxOrder = 0;
    group.processedCollections.forEach(collection => {
      collection.processedRules.forEach(rule => {
        if (rule.processingOrder > maxOrder) {
          maxOrder = rule.processingOrder;
        }
      });
    });
    return maxOrder;
  }

  /**
   * Get maximum processing order from collections
   */
  private static getMaxProcessingOrderFromCollections(collections: ProcessedRuleCollection[]): number {
    let maxOrder = 0;
    collections.forEach(collection => {
      collection.processedRules.forEach(rule => {
        if (rule.processingOrder > maxOrder) {
          maxOrder = rule.processingOrder;
        }
      });
    });
    return maxOrder;
  }

  /**
   * Get all processed rules in processing order
   */
  static getAllRulesInProcessingOrder(groups: ProcessedRuleCollectionGroup[]): ProcessedRule[] {
    const allRules: ProcessedRule[] = [];
    
    groups.forEach(group => {
      group.processedCollections.forEach(collection => {
        allRules.push(...collection.processedRules);
      });
    });

    return allRules.sort((a, b) => a.processingOrder - b.processingOrder);
  }

  /**
   * Get rules by category
   */
  static getRulesByCategory(
    groups: ProcessedRuleCollectionGroup[],
    category: 'DNAT' | 'Network' | 'Application'
  ): ProcessedRule[] {
    const allRules = this.getAllRulesInProcessingOrder(groups);
    return allRules.filter(rule => rule.ruleCategory === category);
  }

  /**
   * Find rule by ID
   */
  static findRuleById(groups: ProcessedRuleCollectionGroup[], ruleId: string): ProcessedRule | null {
    for (const group of groups) {
      for (const collection of group.processedCollections) {
        const rule = collection.processedRules.find(r => r.id === ruleId);
        if (rule) {
          return rule;
        }
      }
    }
    return null;
  }

  /**
   * Get processing statistics
   */
  static getProcessingStatistics(groups: ProcessedRuleCollectionGroup[]) {
    const stats = {
      totalGroups: groups.length,
      totalCollections: 0,
      totalRules: 0,
      parentPolicyGroups: 0,
      childPolicyGroups: 0,
      rulesByCategory: {
        DNAT: 0,
        Network: 0,
        Application: 0,
      },
      priorityRanges: {
        groups: { min: Infinity, max: -Infinity },
        collections: { min: Infinity, max: -Infinity },
      },
    };

    groups.forEach(group => {
      stats.totalCollections += group.processedCollections.length;
      stats.priorityRanges.groups.min = Math.min(stats.priorityRanges.groups.min, group.priority);
      stats.priorityRanges.groups.max = Math.max(stats.priorityRanges.groups.max, group.priority);

      if (group.isParentPolicy) {
        stats.parentPolicyGroups++;
      } else {
        stats.childPolicyGroups++;
      }

      group.processedCollections.forEach(collection => {
        stats.totalRules += collection.processedRules.length;
        stats.priorityRanges.collections.min = Math.min(
          stats.priorityRanges.collections.min,
          collection.priority
        );
        stats.priorityRanges.collections.max = Math.max(
          stats.priorityRanges.collections.max,
          collection.priority
        );

        collection.processedRules.forEach(rule => {
          stats.rulesByCategory[rule.ruleCategory]++;
        });
      });
    });

    return stats;
  }

  /**
   * Validate rule processing order
   */
  static validateProcessingOrder(groups: ProcessedRuleCollectionGroup[]): Array<{ type: string; message: string }> {
    const warnings: Array<{ type: string; message: string }> = [];
    const allRules = this.getAllRulesInProcessingOrder(groups);

    // Check for processing order gaps
    for (let i = 1; i < allRules.length; i++) {
      if (allRules[i].processingOrder !== allRules[i - 1].processingOrder + 1) {
        warnings.push({
          type: 'processing_gap',
          message: `Processing order gap between rules ${allRules[i - 1].name} (order: ${allRules[i - 1].processingOrder}) and ${allRules[i].name} (order: ${allRules[i].processingOrder})`
        });
      }
    }

    // Check for same priority rule collection groups
    const groupPriorities = new Map<number, string[]>();
    groups.forEach(group => {
      if (!groupPriorities.has(group.priority)) {
        groupPriorities.set(group.priority, []);
      }
      groupPriorities.get(group.priority)!.push(group.name);
    });

    groupPriorities.forEach((groupNames, priority) => {
      if (groupNames.length > 1) {
        warnings.push({
          type: 'duplicate_priority',
          message: `Multiple rule collection groups have the same priority ${priority}: ${groupNames.join(', ')}`
        });
      }
    });

    return warnings;
  }
}