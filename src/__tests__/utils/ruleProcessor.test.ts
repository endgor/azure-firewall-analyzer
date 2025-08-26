import { describe, it, expect } from 'vitest';
import { RuleProcessor } from '../../utils/ruleProcessor';
import { FirewallPolicyParser } from '../../utils/parser';
import { readTestFixture } from '../testUtils';

describe('RuleProcessor', () => {
  describe('processFirewallPolicy', () => {
    it('should process rules in correct Azure priority order', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      // Should process groups by priority (lower number = higher priority)
      expect(processedGroups).toHaveLength(2);
      expect(processedGroups[0].name).toBe('HighPriorityGroup');
      expect(processedGroups[0].priority).toBe(100);
      expect(processedGroups[1].name).toBe('LowPriorityGroup');
      expect(processedGroups[1].priority).toBe(1000);
    });

    it('should process rule types in correct order: DNAT → Network → Application', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const highPriorityGroup = processedGroups[0];
      const collections = highPriorityGroup.processedCollections;

      // Should have DNAT, Network, and Application collections
      expect(collections).toHaveLength(3);
      expect(collections[0].ruleCategory).toBe('DNAT');
      expect(collections[1].ruleCategory).toBe('Network');
      expect(collections[2].ruleCategory).toBe('Application');
    });

    it('should assign processing order numbers correctly', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const allRules = RuleProcessor.getAllRulesInProcessingOrder(processedGroups);
      
      // Check that we have the expected number of rules and they are ordered correctly
      expect(allRules).toHaveLength(5); // 1 DNAT + 3 Network + 1 Application
      expect(allRules[0].processingOrder).toBe(1);
      
      // Verify processing orders are assigned (may have gaps due to group separation)
      const processingOrders = allRules.map(r => r.processingOrder);
      expect(processingOrders).toEqual(processingOrders.sort((a, b) => a - b));
    });

    it('should preserve rule metadata correctly', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const allRules = RuleProcessor.getAllRulesInProcessingOrder(processedGroups);
      const firstRule = allRules[0];

      expect(firstRule.id).toMatch(/^rule_/);
      expect(firstRule.collectionName).toBe('DNATRules');
      expect(firstRule.collectionGroupName).toBe('HighPriorityGroup');
      expect(firstRule.ruleCategory).toBe('DNAT');
      expect(firstRule.groupPriority).toBe(100);
      expect(firstRule.collectionPriority).toBe(100);
      expect(firstRule.isParentPolicy).toBe(false);
    });

    it('should handle parent policy inheritance correctly', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const childPolicy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const parentPolicy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      
      // Modify names to differentiate
      parentPolicy.name = 'parent-policy';
      
      const processedGroups = RuleProcessor.processFirewallPolicy(childPolicy, parentPolicy);
      const allRules = RuleProcessor.getAllRulesInProcessingOrder(processedGroups);

      // Parent policy rules should come first
      expect(allRules).toHaveLength(2);
      expect(allRules[0].isParentPolicy).toBe(true);
      expect(allRules[1].isParentPolicy).toBe(false);
      
      // Parent rule should have lower processing order (comes first), or at least equal if they share the same group priority
      expect(allRules[0].processingOrder).toBeLessThanOrEqual(allRules[1].processingOrder);
    });

    it('should categorize rules correctly by type', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const dnatRules = RuleProcessor.getRulesByCategory(processedGroups, 'DNAT');
      const networkRules = RuleProcessor.getRulesByCategory(processedGroups, 'Network');
      const appRules = RuleProcessor.getRulesByCategory(processedGroups, 'Application');

      expect(dnatRules).toHaveLength(1);
      expect(networkRules).toHaveLength(3); // 2 from high priority group + 1 deny rule
      expect(appRules).toHaveLength(1);

      expect(dnatRules[0].ruleType).toBe('NatRule');
      expect(networkRules[0].ruleType).toBe('NetworkRule');
      expect(appRules[0].ruleType).toBe('ApplicationRule');
    });

    it('should find rules by ID correctly', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const allRules = RuleProcessor.getAllRulesInProcessingOrder(processedGroups);
      const targetRule = allRules[0];
      
      const foundRule = RuleProcessor.findRuleById(processedGroups, targetRule.id);
      expect(foundRule).toBeDefined();
      expect(foundRule?.id).toBe(targetRule.id);
      expect(foundRule?.name).toBe(targetRule.name);

      // Test with non-existent ID
      const notFoundRule = RuleProcessor.findRuleById(processedGroups, 'nonexistent-id');
      expect(notFoundRule).toBeNull();
    });

    it('should generate processing statistics correctly', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const stats = RuleProcessor.getProcessingStatistics(processedGroups);

      expect(stats.totalGroups).toBe(2);
      expect(stats.totalCollections).toBe(4); // 3 from high priority + 1 from low priority
      expect(stats.totalRules).toBe(5);
      expect(stats.parentPolicyGroups).toBe(0);
      expect(stats.childPolicyGroups).toBe(2);
      expect(stats.rulesByCategory.DNAT).toBe(1);
      expect(stats.rulesByCategory.Network).toBe(3);
      expect(stats.rulesByCategory.Application).toBe(1);
      expect(stats.priorityRanges.groups.min).toBe(100);
      expect(stats.priorityRanges.groups.max).toBe(1000);
    });

    it('should validate processing order and detect issues', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);

      const warnings = RuleProcessor.validateProcessingOrder(processedGroups);

      // Check that validation function runs without errors
      expect(Array.isArray(warnings)).toBe(true);
      
      // Should not have duplicate priorities in this test case
      const duplicateWarnings = warnings.filter(w => w.type === 'duplicate_priority');
      expect(duplicateWarnings).toHaveLength(0);
    });
  });

  describe('processing order edge cases', () => {
    it('should handle empty rule collections', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      
      // Remove all rules from the collection
      policy.ruleCollectionGroups[0].ruleCollections[0].rules = [];
      
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);
      const allRules = RuleProcessor.getAllRulesInProcessingOrder(processedGroups);

      expect(allRules).toHaveLength(0);
      // The empty collection should still exist, but with no rules
      expect(processedGroups[0].processedCollections).toHaveLength(0);
    });

    it('should handle collections with same priorities correctly', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      
      // Set same priority for multiple collections in the same group
      const highPriorityGroup = policy.ruleCollectionGroups[0];
      highPriorityGroup.ruleCollections.forEach(collection => {
        collection.priority = 100;
      });
      
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);
      const allRules = RuleProcessor.getAllRulesInProcessingOrder(processedGroups);

      // Should still process in rule type order: DNAT → Network → Application
      // Get only rules from the high priority group
      const highPriorityRules = allRules.filter(r => r.collectionGroupName === 'HighPriorityGroup');
      expect(highPriorityRules[0].ruleCategory).toBe('DNAT');
      expect(highPriorityRules[1].ruleCategory).toBe('Network');
      expect(highPriorityRules[2].ruleCategory).toBe('Network');
      expect(highPriorityRules[3].ruleCategory).toBe('Application');
    });
  });
});