import type { ProcessedRule, ProcessedRuleCollectionGroup } from '../types/firewall.types';

export interface RuleFingerprint {
  sourceAddresses: string[];
  destinationAddresses: string[];
  destinationPorts: string[];
  ipProtocols: string[];
  targetFqdns: string[];
  ruleType: string;
}

export interface DuplicateGroup {
  id: string;
  fingerprint: RuleFingerprint;
  rules: ProcessedRule[];
  type: 'exact_duplicate' | 'similar_rules';
  description: string;
}

export interface RuleConflict {
  id: string;
  conflictType: 'allow_deny_conflict' | 'priority_conflict' | 'overlapping_rules';
  description: string;
  rules: {
    primary: ProcessedRule;
    conflicting: ProcessedRule;
  };
  severity: 'high' | 'medium' | 'low';
}

export interface RuleAnalysis {
  duplicates: DuplicateGroup[];
  conflicts: RuleConflict[];
  statistics: {
    totalRules: number;
    duplicateRules: number;
    conflictingRules: number;
    duplicateGroups: number;
    conflicts: number;
  };
}

/**
 * Rule analyzer for detecting duplicates and conflicts in firewall policies
 */
export class RuleAnalyzer {
  /**
   * Analyze all rules for duplicates and conflicts
   */
  static analyzeRules(groups: ProcessedRuleCollectionGroup[]): RuleAnalysis {
    const allRules = this.getAllRulesFlat(groups);
    const duplicates = this.findDuplicateRules(allRules);
    const conflicts = this.findRuleConflicts(allRules);

    const duplicateRulesCount = duplicates.reduce((sum, group) => sum + group.rules.length, 0);
    const conflictingRulesCount = new Set([
      ...conflicts.map(c => c.rules.primary.id),
      ...conflicts.map(c => c.rules.conflicting.id)
    ]).size;

    return {
      duplicates,
      conflicts,
      statistics: {
        totalRules: allRules.length,
        duplicateRules: duplicateRulesCount,
        conflictingRules: conflictingRulesCount,
        duplicateGroups: duplicates.length,
        conflicts: conflicts.length,
      }
    };
  }

  /**
   * Get all rules from groups as a flat array
   */
  private static getAllRulesFlat(groups: ProcessedRuleCollectionGroup[]): ProcessedRule[] {
    const rules: ProcessedRule[] = [];
    groups.forEach(group => {
      group.processedCollections.forEach(collection => {
        rules.push(...collection.processedRules);
      });
    });
    return rules;
  }

  /**
   * Find duplicate rules based on their network characteristics
   */
  static findDuplicateRules(rules: ProcessedRule[]): DuplicateGroup[] {
    const fingerprintMap = new Map<string, ProcessedRule[]>();
    
    // Group rules by their network fingerprint
    rules.forEach(rule => {
      const fingerprint = this.generateRuleFingerprint(rule);
      const fingerprintKey = this.serializeFingerprint(fingerprint);
      
      if (!fingerprintMap.has(fingerprintKey)) {
        fingerprintMap.set(fingerprintKey, []);
      }
      fingerprintMap.get(fingerprintKey)!.push(rule);
    });

    // Find groups with more than one rule (duplicates)
    const duplicateGroups: DuplicateGroup[] = [];
    let duplicateGroupId = 1;

    fingerprintMap.forEach((groupRules, fingerprintKey) => {
      if (groupRules.length > 1) {
        const fingerprint = this.deserializeFingerprint(fingerprintKey);
        const isExactDuplicate = this.areRulesExactDuplicates(groupRules);
        
        duplicateGroups.push({
          id: `duplicate_${duplicateGroupId++}`,
          fingerprint,
          rules: groupRules,
          type: isExactDuplicate ? 'exact_duplicate' : 'similar_rules',
          description: this.generateDuplicateDescription(fingerprint, groupRules, isExactDuplicate)
        });
      }
    });

    return duplicateGroups;
  }

  /**
   * Find conflicts between rules
   */
  static findRuleConflicts(rules: ProcessedRule[]): RuleConflict[] {
    const conflicts: RuleConflict[] = [];
    let conflictId = 1;

    // Sort rules by processing order for conflict analysis
    const sortedRules = [...rules].sort((a, b) => a.processingOrder - b.processingOrder);

    for (let i = 0; i < sortedRules.length; i++) {
      for (let j = i + 1; j < sortedRules.length; j++) {
        const rule1 = sortedRules[i];
        const rule2 = sortedRules[j];

        const conflict = this.detectConflictBetweenRules(rule1, rule2);
        if (conflict) {
          conflicts.push({
            id: `conflict_${conflictId++}`,
            conflictType: conflict.type,
            description: conflict.description,
            rules: {
              primary: rule1,
              conflicting: rule2
            },
            severity: conflict.severity
          });
        }
      }
    }

    return conflicts;
  }

  /**
   * Generate a network fingerprint for a rule
   */
  private static generateRuleFingerprint(rule: ProcessedRule): RuleFingerprint {
    return {
      sourceAddresses: this.normalizeAddresses(rule.sourceAddresses || []),
      destinationAddresses: this.normalizeAddresses(rule.destinationAddresses || []),
      destinationPorts: this.normalizePorts(rule.destinationPorts || []),
      ipProtocols: this.normalizeProtocols(rule.ipProtocols || []),
      targetFqdns: this.normalizeFqdns(rule.targetFqdns || []),
      ruleType: rule.ruleType
    };
  }

  /**
   * Normalize addresses for comparison (sort and lowercase)
   */
  private static normalizeAddresses(addresses: string[]): string[] {
    return addresses.map(addr => addr.toLowerCase().trim()).sort();
  }

  /**
   * Normalize ports for comparison
   */
  private static normalizePorts(ports: string[]): string[] {
    return ports.map(port => port.trim()).sort();
  }

  /**
   * Normalize protocols for comparison
   */
  private static normalizeProtocols(protocols: string[]): string[] {
    return protocols.map(proto => proto.toLowerCase().trim()).sort();
  }

  /**
   * Normalize FQDNs for comparison
   */
  private static normalizeFqdns(fqdns: string[]): string[] {
    return fqdns.map(fqdn => fqdn.toLowerCase().trim()).sort();
  }

  /**
   * Serialize fingerprint to string for map key
   */
  private static serializeFingerprint(fingerprint: RuleFingerprint): string {
    return JSON.stringify({
      sa: fingerprint.sourceAddresses,
      da: fingerprint.destinationAddresses,
      dp: fingerprint.destinationPorts,
      ip: fingerprint.ipProtocols,
      fq: fingerprint.targetFqdns,
      rt: fingerprint.ruleType
    });
  }

  /**
   * Deserialize fingerprint from string
   */
  private static deserializeFingerprint(fingerprintKey: string): RuleFingerprint {
    const data = JSON.parse(fingerprintKey);
    return {
      sourceAddresses: data.sa,
      destinationAddresses: data.da,
      destinationPorts: data.dp,
      ipProtocols: data.ip,
      targetFqdns: data.fq,
      ruleType: data.rt
    };
  }

  /**
   * Check if rules are exact duplicates (same name and collection)
   */
  private static areRulesExactDuplicates(rules: ProcessedRule[]): boolean {
    if (rules.length < 2) return false;
    
    const firstRule = rules[0];
    return rules.every(rule => 
      rule.name === firstRule.name && 
      rule.collectionName === firstRule.collectionName
    );
  }

  /**
   * Generate description for duplicate group
   */
  private static generateDuplicateDescription(
    fingerprint: RuleFingerprint, 
    rules: ProcessedRule[], 
    isExact: boolean
  ): string {
    const ruleNames = rules.map(r => `"${r.name}"`).join(', ');
    const collections = [...new Set(rules.map(r => r.collectionName))].join(', ');
    
    if (isExact) {
      return `Exact duplicate rules found: ${ruleNames} in collections: ${collections}`;
    }
    
    const sourceDesc = fingerprint.sourceAddresses.length > 0 
      ? fingerprint.sourceAddresses.slice(0, 2).join(', ') + (fingerprint.sourceAddresses.length > 2 ? '...' : '')
      : 'Any';
    
    const destDesc = fingerprint.destinationAddresses.length > 0
      ? fingerprint.destinationAddresses.slice(0, 2).join(', ') + (fingerprint.destinationAddresses.length > 2 ? '...' : '')
      : fingerprint.targetFqdns.length > 0
      ? fingerprint.targetFqdns.slice(0, 2).join(', ') + (fingerprint.targetFqdns.length > 2 ? '...' : '')
      : 'Any';
    
    const portDesc = fingerprint.destinationPorts.length > 0
      ? fingerprint.destinationPorts.slice(0, 2).join(', ') + (fingerprint.destinationPorts.length > 2 ? '...' : '')
      : 'Any';

    return `Similar rules with matching traffic pattern: ${sourceDesc} → ${destDesc}:${portDesc}. Rules: ${ruleNames}`;
  }

  /**
   * Detect conflicts between two rules
   */
  private static detectConflictBetweenRules(rule1: ProcessedRule, rule2: ProcessedRule): {
    type: RuleConflict['conflictType'];
    description: string;
    severity: RuleConflict['severity'];
  } | null {
    // Skip if rules are of different types (can't directly conflict)
    if (rule1.ruleType !== rule2.ruleType) {
      return null;
    }

    const fingerprint1 = this.generateRuleFingerprint(rule1);
    const fingerprint2 = this.generateRuleFingerprint(rule2);

    // Check if rules have overlapping traffic patterns
    const hasOverlappingTraffic = this.hasOverlappingTrafficPattern(fingerprint1, fingerprint2);
    
    if (!hasOverlappingTraffic) {
      return null;
    }

    // For Network and Application rules, check for allow/deny conflicts
    if (rule1.ruleType === 'NetworkRule' || rule1.ruleType === 'ApplicationRule') {
      const action1 = this.getRuleAction(rule1);
      const action2 = this.getRuleAction(rule2);

      if (action1 !== action2) {
        return {
          type: 'allow_deny_conflict',
          description: `Rule "${rule1.name}" (${action1}) conflicts with rule "${rule2.name}" (${action2}) - same traffic pattern but different actions`,
          severity: 'high'
        };
      }
    }

    // Check for priority conflicts (rules that will never be reached)
    if (rule1.processingOrder < rule2.processingOrder) {
      const isSamePattern = this.areTrafficPatternsIdentical(fingerprint1, fingerprint2);
      if (isSamePattern) {
        return {
          type: 'priority_conflict',
          description: `Rule "${rule2.name}" (#${rule2.processingOrder}) will never be reached due to identical earlier rule "${rule1.name}" (#${rule1.processingOrder})`,
          severity: 'medium'
        };
      }
    }

    // Check for overlapping rules that might cause confusion
    return {
      type: 'overlapping_rules',
      description: `Rules "${rule1.name}" and "${rule2.name}" have overlapping traffic patterns which may cause unexpected behavior`,
      severity: 'low'
    };
  }

  /**
   * Get the action (Allow/Deny) for a rule based on its collection
   */
  private static getRuleAction(rule: ProcessedRule): string {
    // This is a simplified approach - in a real implementation, you'd need to
    // check the rule collection's action property from the original data
    // For now, we'll assume based on rule category and naming patterns
    const ruleName = rule.name.toLowerCase();
    const collectionName = rule.collectionName.toLowerCase();
    
    if (ruleName.includes('deny') || ruleName.includes('block') || 
        collectionName.includes('deny') || collectionName.includes('block')) {
      return 'Deny';
    }
    
    return 'Allow'; // Default assumption for most firewall rules
  }

  /**
   * Check if two traffic patterns have overlapping characteristics
   */
  private static hasOverlappingTrafficPattern(fp1: RuleFingerprint, fp2: RuleFingerprint): boolean {
    // Check source addresses overlap
    if (!this.hasArrayOverlap(fp1.sourceAddresses, fp2.sourceAddresses)) {
      return false;
    }

    // Check destination addresses/FQDNs overlap
    const dest1 = [...fp1.destinationAddresses, ...fp1.targetFqdns];
    const dest2 = [...fp2.destinationAddresses, ...fp2.targetFqdns];
    if (!this.hasArrayOverlap(dest1, dest2)) {
      return false;
    }

    // Check ports overlap
    if (!this.hasArrayOverlap(fp1.destinationPorts, fp2.destinationPorts)) {
      return false;
    }

    // Check protocols overlap
    if (!this.hasArrayOverlap(fp1.ipProtocols, fp2.ipProtocols)) {
      return false;
    }

    return true;
  }

  /**
   * Check if traffic patterns are identical
   */
  private static areTrafficPatternsIdentical(fp1: RuleFingerprint, fp2: RuleFingerprint): boolean {
    return (
      this.arraysEqual(fp1.sourceAddresses, fp2.sourceAddresses) &&
      this.arraysEqual(fp1.destinationAddresses, fp2.destinationAddresses) &&
      this.arraysEqual(fp1.targetFqdns, fp2.targetFqdns) &&
      this.arraysEqual(fp1.destinationPorts, fp2.destinationPorts) &&
      this.arraysEqual(fp1.ipProtocols, fp2.ipProtocols)
    );
  }

  /**
   * Check if two arrays have any overlapping elements
   */
  private static hasArrayOverlap(arr1: string[], arr2: string[]): boolean {
    if (arr1.length === 0 || arr2.length === 0) {
      return true; // Empty array means "any", so it overlaps with everything
    }
    
    return arr1.some(item => arr2.includes(item));
  }

  /**
   * Check if two arrays are equal
   */
  private static arraysEqual(arr1: string[], arr2: string[]): boolean {
    if (arr1.length !== arr2.length) return false;
    return arr1.every(item => arr2.includes(item));
  }

  /**
   * Get rules that are duplicates of a specific rule
   */
  static findDuplicatesOfRule(rule: ProcessedRule, allRules: ProcessedRule[]): ProcessedRule[] {
    const ruleFingerprint = this.generateRuleFingerprint(rule);
    const ruleFingerprintKey = this.serializeFingerprint(ruleFingerprint);
    
    return allRules.filter(r => {
      if (r.id === rule.id) return false; // Exclude the rule itself
      const otherFingerprint = this.generateRuleFingerprint(r);
      const otherFingerprintKey = this.serializeFingerprint(otherFingerprint);
      return ruleFingerprintKey === otherFingerprintKey;
    });
  }

  /**
   * Get conflicts involving a specific rule
   */
  static findConflictsInvolvingRule(rule: ProcessedRule, allRules: ProcessedRule[]): RuleConflict[] {
    const conflicts = this.findRuleConflicts(allRules);
    return conflicts.filter(conflict => 
      conflict.rules.primary.id === rule.id || 
      conflict.rules.conflicting.id === rule.id
    );
  }
}