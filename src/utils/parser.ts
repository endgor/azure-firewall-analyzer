import type { 
  FirewallPolicy, 
  RuleCollectionGroup, 
  RuleCollection,
  FirewallRule,
  ApplicationRule,
  NetworkRule,
  NatRule,
  FilterRuleCollection,
  NatRuleCollection
} from '../types/firewall.types';

interface AzureTemplate {
  $schema: string;
  contentVersion: string;
  parameters: Record<string, any>;
  variables?: Record<string, any>;
  resources: any[];
}

interface AzureFirewallPolicyResource {
  type: string;
  apiVersion: string;
  name: string;
  location: string;
  tags?: Record<string, string>;
  identity?: any;
  properties: any;
  dependsOn?: string[];
}

interface AzureRuleCollectionGroupResource {
  type: string;
  apiVersion: string;
  name: string;
  location: string;
  dependsOn: string[];
  properties: {
    priority: number;
    ruleCollections: any[];
  };
}

export class FirewallPolicyParser {
  /**
   * Parse Azure Firewall Policy JSON export
   */
  static parseFirewallPolicy(jsonContent: string): FirewallPolicy {
    try {
      const template: AzureTemplate = JSON.parse(jsonContent);
      
      if (!template.resources || !Array.isArray(template.resources)) {
        throw new Error('Invalid template: missing resources array');
      }

      // Find the main firewall policy resource
      const policyResource = template.resources.find(
        (resource) => resource.type === 'Microsoft.Network/firewallPolicies'
      ) as AzureFirewallPolicyResource;

      if (!policyResource) {
        throw new Error('No firewall policy found in template');
      }

      // Find rule collection group resources
      const ruleCollectionGroupResources = template.resources.filter(
        (resource) => resource.type === 'Microsoft.Network/firewallPolicies/ruleCollectionGroups'
      ) as AzureRuleCollectionGroupResource[];

      // Parse the main policy
      const policy: FirewallPolicy = {
        type: policyResource.type as 'Microsoft.Network/firewallPolicies',
        apiVersion: policyResource.apiVersion,
        name: this.extractPolicyName(policyResource.name),
        location: policyResource.location,
        tags: policyResource.tags,
        identity: policyResource.identity,
        properties: this.parseFirewallPolicyProperties(policyResource.properties),
        ruleCollectionGroups: ruleCollectionGroupResources.map(this.parseRuleCollectionGroup.bind(this))
      };

      this.validateParsedPolicy(policy);
      return policy;

    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('Invalid JSON format');
      }
      throw error;
    }
  }

  /**
   * Extract policy name from ARM template expression
   */
  private static extractPolicyName(nameExpression: string): string {
    // Handle ARM template expressions like "[parameters('firewallPolicies_name')]"
    if (nameExpression.startsWith('[') && nameExpression.endsWith(']')) {
      const match = nameExpression.match(/parameters\('([^']+)'\)/);
      if (match) {
        return match[1];
      }
    }
    return nameExpression;
  }

  /**
   * Parse firewall policy properties
   */
  private static parseFirewallPolicyProperties(properties: any): FirewallPolicy['properties'] {
    return {
      sku: {
        tier: properties.sku?.tier || 'Standard'
      },
      threatIntelMode: properties.threatIntelMode || 'Alert',
      dnsSettings: properties.dnsSettings ? {
        servers: properties.dnsSettings.servers || [],
        enableProxy: properties.dnsSettings.enableProxy || false
      } : undefined,
      snat: properties.snat ? {
        privateRanges: properties.snat.privateRanges || []
      } : undefined,
      intrusionDetection: properties.intrusionDetection ? {
        mode: properties.intrusionDetection.mode || 'Off',
        configuration: properties.intrusionDetection.configuration ? {
          signatureOverrides: properties.intrusionDetection.configuration.signatureOverrides || [],
          bypassTrafficSettings: properties.intrusionDetection.configuration.bypassTrafficSettings || []
        } : undefined
      } : undefined,
      transportSecurity: properties.transportSecurity ? {
        certificateAuthority: {
          name: properties.transportSecurity.certificateAuthority.name,
          keyVaultSecretId: properties.transportSecurity.certificateAuthority.keyVaultSecretId
        }
      } : undefined
    };
  }

  /**
   * Parse rule collection group
   */
  private static parseRuleCollectionGroup(resource: AzureRuleCollectionGroupResource): RuleCollectionGroup {
    const groupName = this.extractGroupName(resource.name);
    
    return {
      name: groupName,
      priority: resource.properties.priority,
      ruleCollections: resource.properties.ruleCollections.map(
        (collection) => this.parseRuleCollection(collection, groupName)
      )
    };
  }

  /**
   * Extract group name from ARM template expression
   */
  private static extractGroupName(nameExpression: string): string {
    // Handle expressions like "[concat(parameters('policy_name'), '/DefaultApplicationRuleCollectionGroup')]"
    const match = nameExpression.match(/\/([^'\/]+)'\)]/);
    if (match) {
      return match[1];
    }
    
    // Handle direct names
    if (nameExpression.includes('/')) {
      const parts = nameExpression.split('/');
      return parts[parts.length - 1].replace(/['\]]/g, '');
    }
    
    return nameExpression;
  }

  /**
   * Parse rule collection
   */
  private static parseRuleCollection(collection: any, _groupName: string): RuleCollection {
    const baseCollection = {
      name: collection.name,
      priority: collection.priority,
      rules: collection.rules?.map((rule: any) => this.parseRule(rule)) || []
    };

    if (collection.ruleCollectionType === 'FirewallPolicyFilterRuleCollection') {
      return {
        ...baseCollection,
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
        action: {
          type: collection.action?.type || 'Allow'
        }
      } as FilterRuleCollection;
    } else if (collection.ruleCollectionType === 'FirewallPolicyNatRuleCollection') {
      return {
        ...baseCollection,
        ruleCollectionType: 'FirewallPolicyNatRuleCollection',
        action: {
          type: 'Dnat'
        }
      } as NatRuleCollection;
    }

    throw new Error(`Unknown rule collection type: ${collection.ruleCollectionType}`);
  }

  /**
   * Parse individual rule
   */
  private static parseRule(rule: any): FirewallRule {
    const baseRule = {
      name: rule.name,
      description: rule.description
    };

    switch (rule.ruleType) {
      case 'ApplicationRule':
        return {
          ...baseRule,
          ruleType: 'ApplicationRule',
          protocols: rule.protocols || [],
          fqdnTags: rule.fqdnTags || [],
          webCategories: rule.webCategories || [],
          targetFqdns: rule.targetFqdns || [],
          targetUrls: rule.targetUrls || [],
          terminateTLS: rule.terminateTLS || false,
          sourceAddresses: rule.sourceAddresses || [],
          destinationAddresses: rule.destinationAddresses || [],
          sourceIpGroups: rule.sourceIpGroups || [],
          httpHeadersToInsert: rule.httpHeadersToInsert || []
        } as ApplicationRule;

      case 'NetworkRule':
        return {
          ...baseRule,
          ruleType: 'NetworkRule',
          ipProtocols: rule.ipProtocols || [],
          sourceAddresses: rule.sourceAddresses || [],
          destinationAddresses: rule.destinationAddresses || [],
          sourceIpGroups: rule.sourceIpGroups || [],
          destinationIpGroups: rule.destinationIpGroups || [],
          destinationPorts: rule.destinationPorts || [],
          destinationFqdns: rule.destinationFqdns
        } as NetworkRule;

      case 'NatRule':
        return {
          ...baseRule,
          ruleType: 'NatRule',
          translatedAddress: rule.translatedAddress,
          translatedPort: rule.translatedPort,
          ipProtocols: rule.ipProtocols || [],
          sourceAddresses: rule.sourceAddresses || [],
          sourceIpGroups: rule.sourceIpGroups || [],
          destinationAddresses: rule.destinationAddresses || [],
          destinationPorts: rule.destinationPorts || []
        } as NatRule;

      default:
        throw new Error(`Unknown rule type: ${rule.ruleType}`);
    }
  }

  /**
   * Validate parsed policy
   */
  private static validateParsedPolicy(policy: FirewallPolicy): void {
    if (!policy.name) {
      throw new Error('Policy name is required');
    }

    if (!policy.ruleCollectionGroups || policy.ruleCollectionGroups.length === 0) {
      throw new Error('No rule collection groups found');
    }

    // Validate rule collection groups
    policy.ruleCollectionGroups.forEach((group, groupIndex) => {
      if (!group.name) {
        throw new Error(`Rule collection group at index ${groupIndex} is missing a name`);
      }

      if (typeof group.priority !== 'number' || group.priority < 100 || group.priority > 65000) {
        throw new Error(`Rule collection group "${group.name}" has invalid priority: ${group.priority}`);
      }

      // Validate rule collections
      group.ruleCollections.forEach((collection, collectionIndex) => {
        if (!collection.name) {
          throw new Error(`Rule collection at index ${collectionIndex} in group "${group.name}" is missing a name`);
        }

        if (typeof collection.priority !== 'number' || collection.priority < 100 || collection.priority > 65000) {
          throw new Error(`Rule collection "${collection.name}" has invalid priority: ${collection.priority}`);
        }
      });
    });
  }

  /**
   * Get summary statistics from parsed policy
   */
  static getPolicySummary(policy: FirewallPolicy) {
    let totalRules = 0;
    let natRules = 0;
    let networkRules = 0;
    let applicationRules = 0;

    policy.ruleCollectionGroups.forEach(group => {
      group.ruleCollections.forEach(collection => {
        totalRules += collection.rules.length;
        collection.rules.forEach(rule => {
          switch (rule.ruleType) {
            case 'NatRule':
              natRules++;
              break;
            case 'NetworkRule':
              networkRules++;
              break;
            case 'ApplicationRule':
              applicationRules++;
              break;
          }
        });
      });
    });

    return {
      totalRuleGroups: policy.ruleCollectionGroups.length,
      totalRuleCollections: policy.ruleCollectionGroups.reduce(
        (sum, group) => sum + group.ruleCollections.length, 0
      ),
      totalRules,
      rulesByType: {
        'DNAT': natRules,
        'Network': networkRules,
        'Application': applicationRules
      },
      threatIntelMode: policy.properties.threatIntelMode,
      idpsMode: policy.properties.intrusionDetection?.mode || 'Off',
      sku: policy.properties.sku.tier
    };
  }
}