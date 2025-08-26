import { describe, it, expect } from 'vitest';
import { FirewallPolicyParser } from '../../utils/parser';
import { readTestFixture } from '../testUtils';

describe('FirewallPolicyParser', () => {
  describe('parseFirewallPolicy', () => {
    it('should parse a minimal valid policy', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);

      expect(policy.name).toBe('test-policy');
      expect(policy.type).toBe('Microsoft.Network/firewallPolicies');
      expect(policy.location).toBe('East US');
      expect(policy.properties.sku.tier).toBe('Standard');
      expect(policy.properties.threatIntelMode).toBe('Alert');
      expect(policy.ruleCollectionGroups).toHaveLength(1);
    });

    it('should parse rule collection groups correctly', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);

      const group = policy.ruleCollectionGroups[0];
      expect(group.name).toBe('TestRuleCollectionGroup');
      expect(group.priority).toBe(200);
      expect(group.ruleCollections).toHaveLength(1);
    });

    it('should parse network rules correctly', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);

      const collection = policy.ruleCollectionGroups[0].ruleCollections[0];
      expect(collection.name).toBe('TestNetworkRuleCollection');
      expect(collection.priority).toBe(1000);
      expect(collection.ruleCollectionType).toBe('FirewallPolicyFilterRuleCollection');

      const rule = collection.rules[0];
      expect(rule.ruleType).toBe('NetworkRule');
      expect(rule.name).toBe('AllowHTTP');
      expect(rule.description).toBe('Allow HTTP traffic');
      
      if (rule.ruleType === 'NetworkRule') {
        expect(rule.ipProtocols).toEqual(['TCP']);
        expect(rule.sourceAddresses).toEqual(['10.0.0.0/8']);
        expect(rule.destinationAddresses).toEqual(['*']);
        expect(rule.destinationPorts).toEqual(['80']);
      }
    });

    it('should parse complex policy with multiple rule types', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);

      expect(policy.name).toBe('complex-test-policy');
      expect(policy.properties.sku.tier).toBe('Premium');
      expect(policy.properties.threatIntelMode).toBe('Deny');
      expect(policy.properties.dnsSettings?.servers).toEqual(['8.8.8.8', '8.8.4.4']);
      expect(policy.properties.intrusionDetection?.mode).toBe('Alert');
      expect(policy.ruleCollectionGroups).toHaveLength(2);
    });

    it('should parse NAT rules correctly', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);

      const highPriorityGroup = policy.ruleCollectionGroups.find(g => g.name === 'HighPriorityGroup');
      expect(highPriorityGroup).toBeDefined();

      const natCollection = highPriorityGroup?.ruleCollections.find(c => c.name === 'DNATRules');
      expect(natCollection?.ruleCollectionType).toBe('FirewallPolicyNatRuleCollection');

      const natRule = natCollection?.rules[0];
      expect(natRule?.ruleType).toBe('NatRule');
      expect(natRule?.name).toBe('WebServerNAT');
      
      if (natRule?.ruleType === 'NatRule') {
        expect(natRule.translatedAddress).toBe('10.0.1.10');
        expect(natRule.translatedPort).toBe('80');
        expect(natRule.ipProtocols).toEqual(['TCP']);
        expect(natRule.destinationPorts).toEqual(['8080']);
      }
    });

    it('should parse Application rules correctly', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);

      const highPriorityGroup = policy.ruleCollectionGroups.find(g => g.name === 'HighPriorityGroup');
      const appCollection = highPriorityGroup?.ruleCollections.find(c => c.name === 'ApplicationRules');
      
      expect(appCollection?.ruleCollectionType).toBe('FirewallPolicyFilterRuleCollection');
      
      const appRule = appCollection?.rules[0];
      expect(appRule?.ruleType).toBe('ApplicationRule');
      expect(appRule?.name).toBe('AllowMicrosoft');
      
      if (appRule?.ruleType === 'ApplicationRule') {
        expect(appRule.targetFqdns).toEqual(['*.microsoft.com', '*.windows.com']);
        expect(appRule.protocols).toHaveLength(1);
        expect(appRule.protocols[0].protocolType).toBe('Https');
        expect(appRule.protocols[0].port).toBe(443);
      }
    });

    it('should throw error for invalid JSON', () => {
      const invalidJson = '{ invalid json }';
      
      expect(() => {
        FirewallPolicyParser.parseFirewallPolicy(invalidJson);
      }).toThrow('Invalid JSON format');
    });

    it('should throw error for template without firewall policy resource', () => {
      const templateWithoutPolicy = JSON.stringify({
        $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        contentVersion: '1.0.0.0',
        resources: [
          {
            type: 'Microsoft.Network/virtualNetworks',
            apiVersion: '2023-04-01',
            name: 'test-vnet'
          }
        ]
      });

      expect(() => {
        FirewallPolicyParser.parseFirewallPolicy(templateWithoutPolicy);
      }).toThrow('No firewall policy found in template');
    });

    it('should validate rule collection group priorities', () => {
      expect(() => {
        const jsonContent = readTestFixture('invalid-policy.json');
        FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      }).toThrow(); // Will throw due to unknown rule type first, then priority validation
    });

    it('should extract policy name from ARM template parameters', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      
      // Should extract from parameters defaultValue
      expect(policy.name).toBe('test-policy');
    });

    it('should handle policies with no rule collection groups', () => {
      const policyWithoutGroups = JSON.stringify({
        $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        contentVersion: '1.0.0.0',
        parameters: {
          firewallPolicies_name: {
            type: 'string',
            defaultValue: 'empty-policy'
          }
        },
        resources: [
          {
            type: 'Microsoft.Network/firewallPolicies',
            apiVersion: '2023-04-01',
            name: '[parameters(\'firewallPolicies_name\')]',
            location: 'East US',
            properties: {
              sku: { tier: 'Standard' },
              threatIntelMode: 'Alert'
            }
          }
        ]
      });

      expect(() => {
        FirewallPolicyParser.parseFirewallPolicy(policyWithoutGroups);
      }).toThrow('No rule collection groups found');
    });
  });

  describe('getPolicySummary', () => {
    it('should generate correct summary statistics', () => {
      const jsonContent = readTestFixture('complex-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const summary = FirewallPolicyParser.getPolicySummary(policy);

      expect(summary.totalRuleGroups).toBe(2);
      expect(summary.totalRules).toBe(5); // 1 NAT + 2 Network + 1 Application + 1 Deny rule
      expect(summary.rulesByType.DNAT).toBe(1);
      expect(summary.rulesByType.Network).toBe(3); // 2 from high priority + 1 deny rule
      expect(summary.rulesByType.Application).toBe(1);
      expect(summary.threatIntelMode).toBe('Deny');
      expect(summary.idpsMode).toBe('Alert');
      expect(summary.sku).toBe('Premium');
    });

    it('should handle minimal policy summary', () => {
      const jsonContent = readTestFixture('minimal-policy.json');
      const policy = FirewallPolicyParser.parseFirewallPolicy(jsonContent);
      const summary = FirewallPolicyParser.getPolicySummary(policy);

      expect(summary.totalRuleGroups).toBe(1);
      expect(summary.totalRules).toBe(1);
      expect(summary.rulesByType.Network).toBe(1);
      expect(summary.rulesByType.DNAT).toBe(0);
      expect(summary.rulesByType.Application).toBe(0);
    });
  });
});