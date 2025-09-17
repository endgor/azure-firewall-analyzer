import type { 
  ActionType,
  ApplicationRule,
  FirewallPolicy, 
  FirewallRule,
  FilterRuleCollection,
  IdpsMode,
  NatRule,
  NatRuleCollection,
  NetworkRule,
  ProtocolType,
  RuleCollection,
  RuleCollectionGroup,
  ThreatIntelMode,
} from '../types/firewall.types';

interface AzureTemplate {
  $schema: string;
  contentVersion: string;
  parameters: Record<string, AzureParameterDefinition>;
  variables?: Record<string, unknown>;
  resources: AzureResource[];
}

interface AzureFirewallPolicyResource {
  type: 'Microsoft.Network/firewallPolicies';
  apiVersion: string;
  name: string;
  location: string;
  tags?: Record<string, string>;
  identity?: AzureFirewallPolicyIdentity;
  properties: AzureFirewallPolicyPropertiesRaw;
  dependsOn?: string[];
}

interface AzureRuleCollectionGroupResource {
  type: 'Microsoft.Network/firewallPolicies/ruleCollectionGroups';
  apiVersion: string;
  name: string;
  location: string;
  dependsOn: string[];
  properties: {
    priority: number;
    ruleCollections: AzureRuleCollectionRaw[];
  };
}

type AzureResource = AzureFirewallPolicyResource | AzureRuleCollectionGroupResource | Record<string, unknown>;

type AzureParameterValue = string | number | boolean | Record<string, unknown> | unknown[];

interface AzureParameterDefinition {
  type?: string;
  defaultValue?: AzureParameterValue;
  value?: AzureParameterValue;
  [key: string]: unknown;
}

interface AzureFirewallPolicyIdentity {
  type?: string;
  userAssignedIdentities?: Record<string, unknown>;
  [key: string]: unknown;
}

interface AzureFirewallPolicyPropertiesRaw {
  sku?: { tier?: string };
  threatIntelMode?: string;
  dnsSettings?: {
    servers?: string[];
    enableProxy?: boolean;
  };
  snat?: {
    privateRanges?: string[];
  };
  intrusionDetection?: {
    mode?: string;
    configuration?: {
      signatureOverrides?: Array<Record<string, unknown>>;
      bypassTrafficSettings?: Array<Record<string, unknown>>;
    };
  };
  transportSecurity?: {
    certificateAuthority: {
      name: string;
      keyVaultSecretId: string;
    };
  };
}

interface AzureRuleCollectionRaw {
  name: string;
  priority: number;
  ruleCollectionType: 'FirewallPolicyFilterRuleCollection' | 'FirewallPolicyNatRuleCollection';
  action?: {
    type?: ActionType;
  };
  rules?: AzureRuleRaw[];
}

interface AzureRuleBaseRaw {
  name: string;
  description?: string;
  ruleType: string;
}

interface AzureApplicationRuleRaw extends AzureRuleBaseRaw {
  ruleType: 'ApplicationRule';
  protocols?: Array<{ protocolType: ProtocolType | string; port: number }>;
  fqdnTags?: string[];
  webCategories?: string[];
  targetFqdns?: string[];
  targetUrls?: string[];
  terminateTLS?: boolean;
  sourceAddresses?: string[];
  destinationAddresses?: string[];
  sourceIpGroups?: string[];
  httpHeadersToInsert?: Array<{ name: string; value: string }>;
}

interface AzureNetworkRuleRaw extends AzureRuleBaseRaw {
  ruleType: 'NetworkRule';
  ipProtocols?: string[];
  sourceAddresses?: string[];
  destinationAddresses?: string[];
  sourceIpGroups?: string[];
  destinationIpGroups?: string[];
  destinationPorts?: string[];
  destinationFqdns?: string[];
}

interface AzureNatRuleRaw extends AzureRuleBaseRaw {
  ruleType: 'NatRule';
  translatedAddress?: string;
  translatedPort?: string;
  ipProtocols?: string[];
  sourceAddresses?: string[];
  sourceIpGroups?: string[];
  destinationAddresses?: string[];
  destinationPorts?: string[];
}

type AzureRuleRaw = AzureApplicationRuleRaw | AzureNetworkRuleRaw | AzureNatRuleRaw;

const isFirewallPolicyResource = (resource: AzureResource): resource is AzureFirewallPolicyResource => {
  return typeof resource === 'object' && resource !== null && 'type' in resource && resource.type === 'Microsoft.Network/firewallPolicies';
};

const isRuleCollectionGroupResource = (
  resource: AzureResource
): resource is AzureRuleCollectionGroupResource => {
  return typeof resource === 'object' && resource !== null && 'type' in resource && resource.type === 'Microsoft.Network/firewallPolicies/ruleCollectionGroups';
};

const toStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map(item => (typeof item === 'string' ? item : String(item ?? '')).trim())
    .filter(Boolean);
};

const isThreatIntelMode = (value: unknown): value is ThreatIntelMode => {
  return value === 'Off' || value === 'Alert' || value === 'Deny';
};

const isIdpsMode = (value: unknown): value is IdpsMode => {
  return value === 'Off' || value === 'Alert' || value === 'Deny';
};

const assertUnreachable = (value: never): never => {
  throw new Error(`Unknown value: ${String(value)}`);
};

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
      const policyResource = template.resources.find(isFirewallPolicyResource);

      if (!policyResource) {
        throw new Error('No firewall policy found in template');
      }

      // Find rule collection group resources
      const ruleCollectionGroupResources = template.resources.filter(isRuleCollectionGroupResource);

      // Parse the main policy
      const policy: FirewallPolicy = {
        type: policyResource.type as 'Microsoft.Network/firewallPolicies',
        apiVersion: policyResource.apiVersion,
        name: this.extractPolicyName(policyResource.name, template.parameters),
        location: policyResource.location,
        tags: policyResource.tags,
        identity: policyResource.identity
          ? {
              type: policyResource.identity.type ?? 'None',
              userAssignedIdentities: policyResource.identity.userAssignedIdentities ?? {},
            }
          : undefined,
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
  private static extractPolicyName(
    nameExpression: string,
    parameters?: Record<string, AzureParameterDefinition>
  ): string {
    // Handle ARM template expressions like "[parameters('firewallPolicies_name')]"
    if (nameExpression.startsWith('[') && nameExpression.endsWith(']')) {
      const match = nameExpression.match(/parameters\('([^']+)'\)/);
      if (match && parameters) {
        const paramName = match[1];
        // Look up the parameter's defaultValue in the parameters section
        const paramDef = parameters[paramName];
        if (paramDef && typeof paramDef.defaultValue === 'string') {
          return paramDef.defaultValue;
        }
        // Fall back to parameter name if no defaultValue found
        return paramName;
      }
    }
    return nameExpression;
  }

  /**
   * Parse firewall policy properties
   */
  private static parseFirewallPolicyProperties(
    properties: AzureFirewallPolicyPropertiesRaw
  ): FirewallPolicy['properties'] {
    const threatIntelMode = isThreatIntelMode(properties.threatIntelMode)
      ? properties.threatIntelMode
      : 'Alert';

    const intrusionDetection = properties.intrusionDetection
      ? {
          mode: isIdpsMode(properties.intrusionDetection.mode)
            ? properties.intrusionDetection.mode
            : 'Off',
          configuration: properties.intrusionDetection.configuration
            ? {
                signatureOverrides: (properties.intrusionDetection.configuration.signatureOverrides || [])
                  .map(rawOverride => {
                    const override = rawOverride as { id?: unknown; mode?: unknown };
                    const id = typeof override.id === 'string' ? override.id : String(override.id ?? '');
                    if (!id) return null;
                    const mode = isIdpsMode(override.mode) ? override.mode : 'Alert';
                    return {
                      id,
                      mode,
                    };
                  })
                  .filter((override): override is { id: string; mode: IdpsMode } => Boolean(override)),
                bypassTrafficSettings: (properties.intrusionDetection.configuration.bypassTrafficSettings || [])
                  .map(rawSetting => {
                    const setting = rawSetting as {
                      name?: unknown;
                      protocol?: unknown;
                      sourceAddresses?: unknown;
                      destinationAddresses?: unknown;
                      sourceIpGroups?: unknown;
                      destinationIpGroups?: unknown;
                      destinationPorts?: unknown;
                    };
                    const name = typeof setting.name === 'string' ? setting.name : String(setting.name ?? '');
                    const protocol = typeof setting.protocol === 'string' ? setting.protocol : String(setting.protocol ?? '');
                    if (!name || !protocol) return null;
                    return {
                      name,
                      protocol,
                      sourceAddresses: toStringArray(setting.sourceAddresses),
                      destinationAddresses: toStringArray(setting.destinationAddresses),
                      sourceIpGroups: toStringArray(setting.sourceIpGroups),
                      destinationIpGroups: toStringArray(setting.destinationIpGroups),
                      destinationPorts: toStringArray(setting.destinationPorts),
                    };
                  })
                  .filter((setting): setting is {
                    name: string;
                    protocol: string;
                    sourceAddresses: string[];
                    destinationAddresses: string[];
                    sourceIpGroups: string[];
                    destinationIpGroups: string[];
                    destinationPorts: string[];
                  } => Boolean(setting)),
              }
            : undefined,
        }
      : undefined;

    return {
      sku: {
        tier: properties.sku?.tier === 'Premium' || properties.sku?.tier === 'Basic'
          ? properties.sku.tier
          : 'Standard'
      },
      threatIntelMode,
      dnsSettings: properties.dnsSettings ? {
        servers: toStringArray(properties.dnsSettings.servers),
        enableProxy: properties.dnsSettings.enableProxy ?? false
      } : undefined,
      snat: properties.snat ? {
        privateRanges: toStringArray(properties.snat.privateRanges)
      } : undefined,
      intrusionDetection,
      transportSecurity: properties.transportSecurity ? {
        certificateAuthority: {
          name: properties.transportSecurity.certificateAuthority?.name || '',
          keyVaultSecretId: properties.transportSecurity.certificateAuthority?.keyVaultSecretId || ''
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
        (collection) => this.parseRuleCollection(collection)
      )
    };
  }

  /**
   * Extract group name from ARM template expression
   */
  private static extractGroupName(nameExpression: string): string {
    // Handle expressions like "[concat(parameters('policy_name'), '/DefaultApplicationRuleCollectionGroup')]"
    const match = nameExpression.match(/\/([^'/]+)'\)]/);
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
  private static parseRuleCollection(collection: AzureRuleCollectionRaw): RuleCollection {
    const baseCollection = {
      name: collection.name,
      priority: collection.priority,
      rules: (collection.rules || []).map(rule => this.parseRule(rule))
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
  private static parseRule(rule: AzureRuleRaw): FirewallRule {
    const baseRule = {
      name: rule.name,
      description: rule.description
    };

    switch (rule.ruleType) {
      case 'ApplicationRule':
        return {
          ...baseRule,
          ruleType: 'ApplicationRule',
          protocols: rule.protocols?.map(protocol => ({
            protocolType: protocol.protocolType as ProtocolType,
            port: protocol.port,
          })) || [],
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
        return assertUnreachable(rule as never);
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
