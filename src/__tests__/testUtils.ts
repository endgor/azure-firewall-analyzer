import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Read a test fixture file and return its contents as a string
 */
export function readTestFixture(filename: string): string {
  const fixturePath = join(__dirname, '../test/fixtures', filename);
  return readFileSync(fixturePath, 'utf-8');
}

/**
 * Helper to create a mock Azure ARM template with custom resources
 */
export function createMockTemplate(resources: any[] = [], parameters: any = {}): string {
  return JSON.stringify({
    $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0',
    parameters,
    resources
  });
}

/**
 * Create a basic firewall policy resource for testing
 */
export function createBasicPolicyResource(name: string = 'test-policy'): any {
  return {
    type: 'Microsoft.Network/firewallPolicies',
    apiVersion: '2023-04-01',
    name: `[parameters('${name}_name')]`,
    location: 'East US',
    properties: {
      sku: {
        tier: 'Standard'
      },
      threatIntelMode: 'Alert'
    }
  };
}

/**
 * Create a rule collection group resource for testing
 */
export function createRuleCollectionGroup(
  policyName: string,
  groupName: string,
  priority: number,
  ruleCollections: any[] = []
): any {
  return {
    type: 'Microsoft.Network/firewallPolicies/ruleCollectionGroups',
    apiVersion: '2023-04-01',
    name: `[concat(parameters('${policyName}_name'), '/${groupName}')]`,
    dependsOn: [
      `[resourceId('Microsoft.Network/firewallPolicies', parameters('${policyName}_name'))]`
    ],
    properties: {
      priority,
      ruleCollections
    }
  };
}

/**
 * Create a network rule for testing
 */
export function createNetworkRule(
  name: string,
  options: {
    description?: string;
    ipProtocols?: string[];
    sourceAddresses?: string[];
    destinationAddresses?: string[];
    destinationPorts?: string[];
  } = {}
): any {
  return {
    ruleType: 'NetworkRule',
    name,
    description: options.description || `Test rule ${name}`,
    ipProtocols: options.ipProtocols || ['TCP'],
    sourceAddresses: options.sourceAddresses || ['10.0.0.0/8'],
    destinationAddresses: options.destinationAddresses || ['*'],
    destinationPorts: options.destinationPorts || ['80']
  };
}

/**
 * Create an application rule for testing
 */
export function createApplicationRule(
  name: string,
  options: {
    description?: string;
    sourceAddresses?: string[];
    targetFqdns?: string[];
    protocols?: Array<{ protocolType: string; port: number }>;
  } = {}
): any {
  return {
    ruleType: 'ApplicationRule',
    name,
    description: options.description || `Test app rule ${name}`,
    sourceAddresses: options.sourceAddresses || ['10.0.0.0/8'],
    targetFqdns: options.targetFqdns || ['*.example.com'],
    protocols: options.protocols || [{ protocolType: 'Https', port: 443 }]
  };
}

/**
 * Create a NAT rule for testing
 */
export function createNatRule(
  name: string,
  options: {
    description?: string;
    translatedAddress?: string;
    translatedPort?: string;
    ipProtocols?: string[];
    sourceAddresses?: string[];
    destinationAddresses?: string[];
    destinationPorts?: string[];
  } = {}
): any {
  return {
    ruleType: 'NatRule',
    name,
    description: options.description || `Test NAT rule ${name}`,
    translatedAddress: options.translatedAddress || '10.0.1.10',
    translatedPort: options.translatedPort || '80',
    ipProtocols: options.ipProtocols || ['TCP'],
    sourceAddresses: options.sourceAddresses || ['*'],
    destinationAddresses: options.destinationAddresses || ['203.0.113.10'],
    destinationPorts: options.destinationPorts || ['8080']
  };
}

/**
 * Create a filter rule collection for testing
 */
export function createFilterRuleCollection(
  name: string,
  priority: number,
  action: 'Allow' | 'Deny' = 'Allow',
  rules: any[] = []
): any {
  return {
    ruleCollectionType: 'FirewallPolicyFilterRuleCollection',
    name,
    priority,
    action: { type: action },
    rules
  };
}

/**
 * Create a NAT rule collection for testing
 */
export function createNatRuleCollection(
  name: string,
  priority: number,
  rules: any[] = []
): any {
  return {
    ruleCollectionType: 'FirewallPolicyNatRuleCollection',
    name,
    priority,
    action: { type: 'Dnat' },
    rules
  };
}

/**
 * Assert that a value is defined (not null or undefined)
 */
export function assertDefined<T>(value: T | null | undefined): asserts value is T {
  if (value === null || value === undefined) {
    throw new Error('Expected value to be defined, but got null or undefined');
  }
}