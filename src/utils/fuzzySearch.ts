import type { ProcessedRule, ProcessedRuleCollection, ProcessedRuleCollectionGroup } from '../types/firewall.types';

const normalize = (value: string) => value.toLowerCase();

const extractFromArray = (values?: Array<string | number | undefined>) => {
  if (!values) return [];
  return values
    .flatMap(value => {
      if (value === undefined || value === null) return [];
      const asString = typeof value === 'string' ? value : String(value);
      return asString.split(/\s*,\s*/); // split combined entries like "80,443"
    })
    .filter(Boolean) as string[];
};

export const buildRuleSearchIndex = (
  rule: ProcessedRule,
  context?: {
    collection?: ProcessedRuleCollection;
    group?: ProcessedRuleCollectionGroup;
  }
) => {
  const values: string[] = [];

  values.push(rule.name, rule.description || '');
  values.push(rule.collectionName, rule.collectionGroupName);
  values.push(rule.ruleType, rule.ruleCategory);

  if (rule.processingOrder !== undefined) {
    values.push(String(rule.processingOrder));
  }
  if (rule.groupPriority !== undefined) {
    values.push(String(rule.groupPriority));
  }
  if (rule.collectionPriority !== undefined) {
    values.push(String(rule.collectionPriority));
  }

  values.push(...extractFromArray(rule.sourceAddresses));
  values.push(...extractFromArray(rule.destinationAddresses));
  values.push(...extractFromArray(rule.sourceIpGroups));
  values.push(...extractFromArray(rule.destinationIpGroups));
  values.push(...extractFromArray(rule.destinationFqdns));
  values.push(...extractFromArray(rule.targetFqdns));
  values.push(...extractFromArray(rule.fqdnTags));
  values.push(...extractFromArray(rule.webCategories));
  values.push(...extractFromArray(rule.destinationPorts));

  if (rule.translatedAddress) {
    values.push(rule.translatedAddress);
  }
  if (rule.translatedPort) {
    values.push(rule.translatedPort);
  }

  if (rule.ipProtocols) {
    values.push(...rule.ipProtocols);
  }
  if (rule.protocols) {
    rule.protocols.forEach(protocol => {
      values.push(protocol.protocolType);
      if (protocol.port !== undefined) {
        values.push(String(protocol.port));
      }
      values.push(`${protocol.protocolType}:${protocol.port}`);
    });
  }

  if (rule.httpHeadersToInsert) {
    rule.httpHeadersToInsert.forEach(header => {
      values.push(header.name);
      values.push(header.value);
    });
  }

  if (context?.collection) {
    const { collection } = context;
    values.push(collection.name);
    values.push(collection.ruleCollectionType);
    if (collection.priority !== undefined) {
      values.push(String(collection.priority));
    }
    if (collection.action?.type) {
      values.push(collection.action.type);
    }
  }

  if (context?.group) {
    const { group } = context;
    values.push(group.name);
    if (group.priority !== undefined) {
      values.push(String(group.priority));
    }
  }

  return values
    .map(value => value ?? '')
    .filter(Boolean)
    .map(value => normalize(value));
};

export const fuzzyMatch = (value: string, query: string) => {
  if (!query) return true;
  if (!value) return false;

  if (value.includes(query)) {
    return true;
  }

  let searchIndex = 0;
  for (const char of query) {
    searchIndex = value.indexOf(char, searchIndex);
    if (searchIndex === -1) {
      return false;
    }
    searchIndex += 1;
  }

  return true;
};
