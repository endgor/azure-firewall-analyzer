import React, { useState, useMemo } from 'react';
import { 
  ChevronRight, 
  ChevronDown, 
  Search, 
  Filter,
  ExternalLink,
  Shield,
  Network,
  Globe,
  Maximize2,
  Minimize2
} from 'lucide-react';
import type { 
  ProcessedRuleCollectionGroup, 
  ProcessedRule,
  RuleType,
  ActionType 
} from '../../types/firewall.types';
import { SingleSelectDropdown } from '../common/Dropdown';

interface RuleTableProps {
  groups: ProcessedRuleCollectionGroup[];
  onRuleSelect?: (rule: ProcessedRule) => void;
  selectedRuleId?: string;
}

export const RuleTable: React.FC<RuleTableProps> = ({
  groups,
  onRuleSelect,
  selectedRuleId
}) => {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [expandedCollections, setExpandedCollections] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [filterByType, setFilterByType] = useState<RuleType | 'all'>('all');
  const [filterByAction, setFilterByAction] = useState<ActionType | 'all'>('all');

  const toggleGroup = (groupId: string) => {
    setExpandedGroups(prev => {
      const newSet = new Set(prev);
      if (newSet.has(groupId)) {
        newSet.delete(groupId);
      } else {
        newSet.add(groupId);
      }
      return newSet;
    });
  };

  const toggleCollection = (collectionId: string) => {
    setExpandedCollections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(collectionId)) {
        newSet.delete(collectionId);
      } else {
        newSet.add(collectionId);
      }
      return newSet;
    });
  };

  const expandAll = () => {
    const allGroupIds = new Set(filteredGroups.map(group => group.id));
    const allCollectionIds = new Set(
      filteredGroups.flatMap(group => 
        group.processedCollections.map(collection => collection.id)
      )
    );
    setExpandedGroups(allGroupIds);
    setExpandedCollections(allCollectionIds);
  };

  const collapseAll = () => {
    setExpandedGroups(new Set());
    setExpandedCollections(new Set());
  };

  const filteredGroups = useMemo(() => {
    return groups.map(group => {
      const filteredCollections = group.processedCollections.map(collection => {
        const filteredRules = collection.processedRules.filter(rule => {
          // Search filter
          if (searchQuery) {
            const query = searchQuery.toLowerCase();
            const matchesSearch = 
              rule.name.toLowerCase().includes(query) ||
              rule.collectionName.toLowerCase().includes(query) ||
              rule.collectionGroupName.toLowerCase().includes(query) ||
              (rule.ruleType === 'ApplicationRule' && rule.targetFqdns?.some((fqdn: string) => fqdn.toLowerCase().includes(query))) ||
              (rule.ruleType === 'NetworkRule' && [
                ...(rule.sourceAddresses || []),
                ...(rule.sourceIpGroups || []),
                ...(rule.destinationAddresses || []),
                ...(rule.destinationIpGroups || []),
                ...(rule.destinationFqdns || []),
              ].some((addr: string) => addr.toLowerCase().includes(query)));
            
            if (!matchesSearch) return false;
          }

          // Type filter
          if (filterByType !== 'all') {
            if (filterByType === 'NatRule' && rule.ruleType !== 'NatRule') return false;
            if (filterByType === 'NetworkRule' && rule.ruleType !== 'NetworkRule') return false;
            if (filterByType === 'ApplicationRule' && rule.ruleType !== 'ApplicationRule') return false;
          }

          // Action filter
          if (filterByAction !== 'all') {
            if (rule.ruleType === 'NatRule' && filterByAction !== 'Dnat') {
              return false;
            }
            // For filter rules, check the collection action
            if (rule.ruleType === 'NetworkRule' || rule.ruleType === 'ApplicationRule') {
              const parentCollection = group.processedCollections.find(c => c.name === rule.collectionName);
              if (parentCollection?.ruleCollectionType === 'FirewallPolicyFilterRuleCollection') {
                if (parentCollection.action?.type !== filterByAction) {
                  return false;
                }
              }
            }
          }

          return true;
        });

        return {
          ...collection,
          processedRules: filteredRules
        };
      }).filter(collection => collection.processedRules.length > 0); // Hide collections with no matching rules

      return {
        ...group,
        processedCollections: filteredCollections
      };
    }).filter(group => group.processedCollections.length > 0); // Hide groups with no matching collections
  }, [groups, searchQuery, filterByType, filterByAction]);

  const getRuleTypeIcon = (ruleType: RuleType) => {
    switch (ruleType) {
      case 'NatRule':
        return <ExternalLink className="w-4 h-4 text-rule-dnat" />;
      case 'NetworkRule':
        return <Network className="w-4 h-4 text-rule-network" />;
      case 'ApplicationRule':
        return <Globe className="w-4 h-4 text-rule-application" />;
      default:
        return <Shield className="w-4 h-4 text-gray-400" />;
    }
  };

  const getRuleTypeColor = (ruleType: RuleType) => {
    switch (ruleType) {
      case 'NatRule':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'NetworkRule':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'ApplicationRule':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getGroupDominantRuleType = (group: ProcessedRuleCollectionGroup) => {
    const ruleCounts = { DNAT: 0, Network: 0, Application: 0 };
    
    group.processedCollections.forEach(collection => {
      collection.processedRules.forEach(rule => {
        if (rule.ruleType === 'NatRule') ruleCounts.DNAT++;
        else if (rule.ruleType === 'NetworkRule') ruleCounts.Network++;
        else if (rule.ruleType === 'ApplicationRule') ruleCounts.Application++;
      });
    });
    
    // Return the dominant type or fallback to mixed
    const maxCount = Math.max(...Object.values(ruleCounts));
    if (maxCount === 0) return 'mixed';
    
    const dominantType = Object.entries(ruleCounts).find(([_, count]) => count === maxCount)?.[0];
    return dominantType || 'mixed';
  };

  const getShieldColorClass = (group: ProcessedRuleCollectionGroup) => {
    const dominantType = getGroupDominantRuleType(group);
    switch (dominantType) {
      case 'DNAT':
        return 'text-rule-dnat';
      case 'Network':
        return 'text-rule-network';
      case 'Application':
        return 'text-rule-application';
      default:
        return 'text-gray-600';
    }
  };

  const formatRuleDetails = (rule: ProcessedRule) => {
    switch (rule.ruleType) {
      case 'ApplicationRule':
        const protocols = rule.protocols?.map((p: any) => `${p.protocolType}:${p.port}`).join(', ') || '';
        const targets = rule.targetFqdns && rule.targetFqdns.length > 0 ? rule.targetFqdns.slice(0, 3).join(', ') : 'Any';
        return `${protocols} → ${targets}${rule.targetFqdns && rule.targetFqdns.length > 3 ? '...' : ''}`;
      
      case 'NetworkRule':
        const ports = rule.destinationPorts?.slice(0, 3).join(', ') || '';
        const destinationList = [
          ...(rule.destinationAddresses || []),
          ...(rule.destinationIpGroups || []),
          ...(rule.destinationFqdns || []),
        ];
        const destinationSummary = destinationList.length > 0
          ? destinationList.slice(0, 2).join(', ')
          : 'Any';
        const hasAdditionalDestinations = destinationList.length > 2;
        return `${rule.ipProtocols?.join(',') || ''}:${ports} → ${destinationSummary}${hasAdditionalDestinations ? '...' : ''}`;
      
      case 'NatRule':
        return `${rule.ipProtocols?.join(',') || ''}:${rule.destinationPorts?.join(',') || ''} → ${rule.translatedAddress}:${rule.translatedPort}`;
      
      default:
        return '';
    }
  };

  const totalVisibleRules = filteredGroups.reduce(
    (sum, group) => sum + group.processedCollections.reduce(
      (collectionSum, collection) => collectionSum + collection.processedRules.length, 0
    ), 0
  );

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      {/* Header with filters */}
      <div className="border-b border-gray-200 p-4 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <h2 className="text-lg font-medium text-gray-900">
              Firewall Rules ({totalVisibleRules} rules)
            </h2>
            {/* Active filters indicator */}
            {(searchQuery || filterByType !== 'all' || filterByAction !== 'all') && (
              <div className="flex items-center space-x-2">
                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-blue-100 text-blue-800">
                  <Filter className="w-3 h-3 mr-1" />
                  Filtered
                </span>
                {totalVisibleRules !== groups.reduce((sum, g) => sum + g.processedCollections.reduce((collSum, c) => collSum + c.processedRules.length, 0), 0) && (
                  <span className="text-xs text-gray-500">
                    {groups.reduce((sum, g) => sum + g.processedCollections.reduce((collSum, c) => collSum + c.processedRules.length, 0), 0) - totalVisibleRules} hidden
                  </span>
                )}
              </div>
            )}
          </div>
          <div className="flex items-center space-x-4">
            {/* Expand/Collapse Controls */}
            <div className="flex items-center space-x-1">
              <button
                onClick={expandAll}
                className="inline-flex items-center px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 rounded hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                title="Expand All"
              >
                <Maximize2 className="w-3 h-3 mr-1" />
                Expand All
              </button>
              <button
                onClick={collapseAll}
                className="inline-flex items-center px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 rounded hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                title="Collapse All"
              >
                <Minimize2 className="w-3 h-3 mr-1" />
                Collapse All
              </button>
            </div>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search rules, collections, or targets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          {/* Filters */}
          <div className="flex gap-2">
            <SingleSelectDropdown
              value={filterByType}
              onChange={(value) => setFilterByType(value as RuleType | 'all')}
              options={[
                { value: 'all', label: 'All Types' },
                { value: 'NatRule', label: 'DNAT' },
                { value: 'NetworkRule', label: 'Network' },
                { value: 'ApplicationRule', label: 'Application' }
              ]}
              placeholder="Filter by type"
              className="w-32"
            />

            <SingleSelectDropdown
              value={filterByAction}
              onChange={(value) => setFilterByAction(value as ActionType | 'all')}
              options={[
                { value: 'all', label: 'All Actions' },
                { value: 'Allow', label: 'Allow' },
                { value: 'Deny', label: 'Deny' },
                { value: 'Dnat', label: 'DNAT' }
              ]}
              placeholder="Filter by action"
              className="w-32"
            />
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-8">
                Order
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Rule/Collection/Group
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Type
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Priority
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Details
              </th>
            </tr>
          </thead>
          <tbody className="bg-white">
            {filteredGroups.map((group) => (
              <React.Fragment key={group.id}>
                {/* Rule Collection Group Row */}
                <tr 
                  className={`border-t-2 border-gray-300 bg-gray-50 cursor-pointer hover:bg-gray-100 ${
                    group.isParentPolicy ? 'bg-blue-50 hover:bg-blue-100' : ''
                  }`}
                  onClick={() => toggleGroup(group.id)}
                >
                  <td className="px-4 py-3 text-sm font-medium text-gray-700">
                    <div className="flex items-center">
                      {expandedGroups.has(group.id) ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm font-medium text-gray-900">
                    <div className="flex items-center">
                      <Shield className={`w-4 h-4 mr-2 ${getShieldColorClass(group)}`} />
                      {group.name}
                      {group.isParentPolicy && (
                        <span className="ml-2 px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">
                          Parent Policy
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    Rule Group
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {group.priority}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {group.processedCollections.length} collections, {' '}
                    {group.processedCollections.reduce((sum, c) => sum + c.processedRules.length, 0)} rules
                  </td>
                </tr>

                {/* Rule Collections */}
                {expandedGroups.has(group.id) && group.processedCollections.map((collection) => (
                  <React.Fragment key={collection.id}>
                    <tr 
                      className="bg-gray-25 cursor-pointer hover:bg-gray-50"
                      onClick={() => toggleCollection(collection.id)}
                    >
                      <td className="px-4 py-2 text-sm text-gray-500"></td>
                      <td className="px-4 py-2 text-sm font-medium text-gray-800">
                        <div className="flex items-center ml-4">
                          {expandedCollections.has(collection.id) ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                          <div className="ml-2">
                            {collection.name}
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-sm">
                        <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${
                          getRuleTypeColor(collection.ruleCategory as RuleType)
                        }`}>
                          {collection.ruleCategory}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-500">
                        {collection.priority}
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-500">
                        {collection.processedRules.length} rules
                      </td>
                    </tr>

                    {/* Individual Rules */}
                    {expandedCollections.has(collection.id) && collection.processedRules.map((rule) => (
                      <tr 
                        key={rule.id}
                        className={`cursor-pointer hover:bg-blue-50 ${
                          selectedRuleId === rule.id ? 'bg-blue-100' : ''
                        }`}
                        onClick={() => onRuleSelect?.(rule)}
                      >
                        <td className="px-4 py-2 text-sm font-medium text-blue-600">
                          #{rule.processingOrder}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-900">
                          <div className="flex items-center ml-8">
                            {getRuleTypeIcon(rule.ruleType)}
                            <span className="ml-2">{rule.name}</span>
                          </div>
                        </td>
                        <td className="px-4 py-2 text-sm">
                          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${
                            getRuleTypeColor(rule.ruleType)
                          }`}>
                            {rule.ruleType.replace('Rule', '')}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-500">
                          {rule.collectionPriority}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-500 font-mono text-xs">
                          {formatRuleDetails(rule)}
                        </td>
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {totalVisibleRules === 0 && (
        <div className="text-center py-8 text-gray-500">
          <Filter className="w-8 h-8 mx-auto mb-2 text-gray-300" />
          <p className="text-lg font-medium mb-2">No rules match your criteria</p>
          <div className="text-sm space-y-1">
            {searchQuery && <p>Search: "{searchQuery}"</p>}
            {filterByType !== 'all' && <p>Type: {filterByType.replace('Rule', '')}</p>}
            {filterByAction !== 'all' && <p>Action: {filterByAction}</p>}
            <p className="text-xs text-gray-400 mt-2">Try adjusting your search terms or filters</p>
          </div>
        </div>
      )}
    </div>
  );
};
