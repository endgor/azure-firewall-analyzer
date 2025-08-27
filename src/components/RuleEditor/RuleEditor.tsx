import { useState, useCallback, useMemo } from 'react';
import { Save, Download, Copy, Trash2, AlertCircle } from 'lucide-react';
import type { ProcessedRule, ProcessedRuleCollectionGroup } from '../../types/firewall.types';
import { exportToDraftJSON, generateAzureCLICommands } from '../../utils/draftExporter';
import { SingleSelectDropdown, MultiSelectDropdown } from '../common/Dropdown';

interface RuleEditorProps {
  groups: ProcessedRuleCollectionGroup[];
  policyName: string;
  onRulesChange: (groups: ProcessedRuleCollectionGroup[]) => void;
}

interface EditableRule extends ProcessedRule {
  isModified?: boolean;
  isNew?: boolean;
}

export function RuleEditor({ groups, policyName, onRulesChange }: RuleEditorProps) {
  const [editingRules, setEditingRules] = useState<{ [key: string]: EditableRule }>({});
  const [showExportModal, setShowExportModal] = useState(false);
  const [resourceGroup, setResourceGroup] = useState('');
  const [subscriptionId, setSubscriptionId] = useState('');

  // Flatten all rules for editing
  const allRules = useMemo(() => {
    const rules: EditableRule[] = [];
    groups.forEach(group => {
      group.ruleCollections.forEach(collection => {
        collection.rules.forEach((rule, index) => {
          const ruleId = `${group.name}-${collection.name}-${index}`;
          const editedRule = editingRules[ruleId];
          const ruleWithId = { 
            ...rule, 
            id: ruleId,
            collectionGroupName: group.name,
            collectionName: collection.name,
            groupPriority: group.priority,
            collectionPriority: collection.priority
          };
          rules.push(editedRule || ruleWithId);
        });
      });
    });
    return rules;
  }, [groups, editingRules]);

  const handleFieldChange = useCallback((ruleId: string, field: string, value: string | string[] | any) => {
    setEditingRules(prev => {
      const existingRule = prev[ruleId] || allRules.find(r => (r as any).id === ruleId);
      if (!existingRule) return prev;

      return {
        ...prev,
        [ruleId]: {
          ...existingRule,
          [field]: value,
          isModified: true,
          // Preserve collection metadata
          collectionGroupName: existingRule.collectionGroupName,
          collectionName: existingRule.collectionName,
          groupPriority: existingRule.groupPriority,
          collectionPriority: existingRule.collectionPriority
        }
      };
    });
  }, [allRules]);

  const handleSaveChanges = useCallback(() => {
    const updatedGroups = groups.map(group => ({
      ...group,
      ruleCollections: group.ruleCollections.map(collection => ({
        ...collection,
        rules: collection.rules.map((rule, index) => {
          const ruleId = `${group.name}-${collection.name}-${index}`;
          const editedRule = editingRules[ruleId];
          return editedRule || { ...rule, id: ruleId };
        }) as any
      }))
    }));

    onRulesChange(updatedGroups);
    setEditingRules({});
  }, [groups, editingRules, onRulesChange]);

  const handleDiscardChanges = useCallback(() => {
    setEditingRules({});
  }, []);

  const handleDeleteRule = useCallback((ruleId: string) => {
    if (confirm('Are you sure you want to delete this rule?')) {
      const updatedGroups = groups.map(group => ({
        ...group,
        ruleCollections: group.ruleCollections.map(collection => ({
          ...collection,
          rules: collection.rules.filter((_rule, index) => {
          const currentRuleId = `${group.name}-${collection.name}-${index}`;
          return currentRuleId !== ruleId;
        })
        }))
      }));

      onRulesChange(updatedGroups);
      
      // Remove from editing rules if present
      setEditingRules(prev => {
        const newState = { ...prev };
        delete newState[ruleId];
        return newState;
      });
    }
  }, [groups, onRulesChange]);

  const handleExportDraft = useCallback(() => {
    if (!resourceGroup.trim()) {
      alert('Please enter a resource group name');
      return;
    }

    const modifiedRules = Object.values(editingRules).filter(rule => rule.isModified);
    
    if (modifiedRules.length === 0) {
      alert('No modified rules to export');
      return;
    }

    // Export modified rules as draft JSON
    const draftData = exportToDraftJSON(modifiedRules);
    const blob = new Blob([JSON.stringify(draftData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${policyName}-draft-rules.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [editingRules, policyName, resourceGroup]);

  const handleCopyCommands = useCallback(() => {
    if (!resourceGroup.trim()) {
      alert('Please enter a resource group name');
      return;
    }

    const modifiedRules = Object.values(editingRules).filter(rule => rule.isModified);
    
    if (modifiedRules.length === 0) {
      alert('No modified rules to generate commands for');
      return;
    }

    const commands = generateAzureCLICommands(modifiedRules, policyName, resourceGroup, subscriptionId);
    navigator.clipboard.writeText(commands).then(() => {
      alert('Azure CLI commands copied to clipboard!');
    }).catch(() => {
      alert('Failed to copy to clipboard. Please copy manually from the export modal.');
    });
  }, [editingRules, policyName, resourceGroup, subscriptionId]);

  const modifiedCount = Object.values(editingRules).filter(rule => rule.isModified).length;
  const hasChanges = modifiedCount > 0;

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-medium text-gray-900">Rule Editor</h2>
          <p className="text-sm text-gray-500">
            Edit firewall rules and export as Azure CLI draft commands
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          {hasChanges && (
            <div className="flex items-center text-amber-600 text-sm">
              <AlertCircle className="w-4 h-4 mr-1" />
              {modifiedCount} rule{modifiedCount !== 1 ? 's' : ''} modified
            </div>
          )}
          
          <button
            onClick={handleDiscardChanges}
            disabled={!hasChanges}
            className="px-3 py-1 text-sm border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Discard Changes
          </button>
          
          <button
            onClick={handleSaveChanges}
            disabled={!hasChanges}
            className="flex items-center px-3 py-1 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="w-4 h-4 mr-1" />
            Save Changes
          </button>
          
          <button
            onClick={() => setShowExportModal(true)}
            disabled={!hasChanges}
            className="flex items-center px-3 py-1 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4 mr-1" />
            Export Draft
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-48">
                Rule Name
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                Type
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                Action
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-40">
                Source
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-40">
                Destination
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">
                Protocol
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">
                Ports
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-32">
                Translated Address
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                Translated Port
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {allRules.map((rule) => {
              const isEdited = editingRules[rule.id]?.isModified;
              
              return (
                <tr key={rule.id} className={isEdited ? 'bg-amber-50' : undefined}>
                  {/* Rule Name */}
                  <td className="px-3 py-4">
                    <input
                      type="text"
                      value={rule.name}
                      onChange={(e) => handleFieldChange(rule.id, 'name', e.target.value)}
                      className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />
                  </td>
                  
                  {/* Type */}
                  <td className="px-3 py-4">
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                      rule.ruleType === 'NatRule' ? 'bg-blue-100 text-blue-800' :
                      rule.ruleType === 'NetworkRule' ? 'bg-green-100 text-green-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {rule.ruleType.replace('Rule', '')}
                    </span>
                  </td>
                  
                  {/* Action */}
                  <td className="px-3 py-4">
                    {rule.ruleType === 'NatRule' ? (
                      <span className="text-sm text-gray-500">DNAT</span>
                    ) : (
                      <SingleSelectDropdown
                        value={(rule as any).action || 'Allow'}
                        onChange={(value) => handleFieldChange(rule.id, 'action', value)}
                        options={[
                          { value: 'Allow', label: 'Allow' },
                          { value: 'Deny', label: 'Deny' }
                        ]}
                      />
                    )}
                  </td>
                  
                  {/* Source */}
                  <td className="px-3 py-4">
                    <input
                      type="text"
                      value={rule.sourceAddresses?.join(', ') || ''}
                      onChange={(e) => handleFieldChange(rule.id, 'sourceAddresses', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                      className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Source addresses"
                    />
                  </td>
                  
                  {/* Destination */}
                  <td className="px-3 py-4">
                    {rule.ruleType === 'ApplicationRule' ? (
                      <input
                        type="text"
                        value={rule.targetFqdns?.join(', ') || ''}
                        onChange={(e) => handleFieldChange(rule.id, 'targetFqdns', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="Target FQDNs"
                      />
                    ) : (
                      <input
                        type="text"
                        value={rule.destinationAddresses?.join(', ') || ''}
                        onChange={(e) => handleFieldChange(rule.id, 'destinationAddresses', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="Destination addresses"
                      />
                    )}
                  </td>
                  
                  {/* Protocol */}
                  <td className="px-3 py-4">
                    {rule.ruleType === 'ApplicationRule' ? (
                      <input
                        type="text"
                        value={rule.protocols?.map((p: any) => p.protocolType).join(', ') || ''}
                        onChange={(e) => {
                          const types = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                          const protocols = types.map(type => ({
                            protocolType: type,
                            port: type === 'Http' ? 80 : type === 'Https' ? 443 : 80
                          }));
                          handleFieldChange(rule.id, 'protocols', protocols);
                        }}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="Http, Https"
                      />
                    ) : (
                      <input
                        type="text"
                        value={rule.ipProtocols?.join(', ') || ''}
                        onChange={(e) => handleFieldChange(rule.id, 'ipProtocols', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="TCP, UDP, ICMP"
                      />
                    )}
                  </td>
                  
                  {/* Ports */}
                  <td className="px-3 py-4">
                    {rule.ruleType === 'ApplicationRule' ? (
                      <input
                        type="text"
                        value={rule.protocols?.map((p: any) => p.port || '80').join(', ') || ''}
                        onChange={(e) => {
                          const ports = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                          const updatedProtocols = rule.protocols?.map((p: any, index: number) => ({
                            ...p,
                            port: parseInt(ports[index] || ports[0] || '80', 10)
                          })) || [];
                          handleFieldChange(rule.id, 'protocols', updatedProtocols);
                        }}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="80, 443, 8080"
                      />
                    ) : (
                      <input
                        type="text"
                        value={rule.destinationPorts?.join(', ') || ''}
                        onChange={(e) => handleFieldChange(rule.id, 'destinationPorts', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="80,443,8080"
                      />
                    )}
                  </td>
                  
                  {/* Translated Address */}
                  <td className="px-3 py-4">
                    {rule.ruleType === 'NatRule' ? (
                      <input
                        type="text"
                        value={rule.translatedAddress || ''}
                        onChange={(e) => handleFieldChange(rule.id, 'translatedAddress', e.target.value)}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="10.0.0.1"
                      />
                    ) : (
                      <span className="text-sm text-gray-400">N/A</span>
                    )}
                  </td>
                  
                  {/* Translated Port */}
                  <td className="px-3 py-4">
                    {rule.ruleType === 'NatRule' ? (
                      <input
                        type="text"
                        value={rule.translatedPort || ''}
                        onChange={(e) => handleFieldChange(rule.id, 'translatedPort', e.target.value)}
                        className="w-full p-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder="3389"
                      />
                    ) : (
                      <span className="text-sm text-gray-400">N/A</span>
                    )}
                  </td>
                  
                  {/* Actions */}
                  <td className="px-3 py-4 text-center">
                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      className="text-red-600 hover:text-red-900"
                      title="Delete rule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        
        {allRules.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-500">No rules to edit. Upload a policy to get started.</p>
          </div>
        )}
      </div>

      {/* Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium text-gray-900">Export Draft Configuration</h3>
              <button
                onClick={() => setShowExportModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <span className="sr-only">Close</span>
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="bg-amber-50 p-4 rounded-md border border-amber-200">
                <h4 className="text-sm font-medium text-amber-900 mb-2 flex items-center">
                  <AlertCircle className="w-4 h-4 mr-2" />
                  Azure Resource Information
                </h4>
                <p className="text-sm text-amber-800">
                  Enter details for your <strong>existing</strong> Azure Firewall Policy. The draft will be created 
                  as a temporary copy in the same location, then deployed to replace the live policy.
                </p>
              </div>

              <div>
                <label htmlFor="subscriptionId" className="flex items-center text-sm font-medium text-gray-700 mb-2">
                  Azure Subscription ID 
                  <span className="text-gray-500 ml-1">(optional)</span>
                </label>
                <input
                  type="text"
                  id="subscriptionId"
                  value={subscriptionId}
                  onChange={(e) => setSubscriptionId(e.target.value)}
                  className="block w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="12345678-1234-1234-1234-123456789012"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Only needed if you have multiple subscriptions or want to be explicit
                </p>
              </div>
              
              <div>
                <label htmlFor="resourceGroup" className="flex items-center text-sm font-medium text-gray-700 mb-2">
                  Resource Group Name 
                  <span className="text-red-500 ml-1">*</span>
                </label>
                <input
                  type="text"
                  id="resourceGroup"
                  value={resourceGroup}
                  onChange={(e) => setResourceGroup(e.target.value)}
                  className="block w-full border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  placeholder="rg-network-prod"
                  required
                />
                <p className="mt-1 text-xs text-gray-500">
                  <strong>Existing</strong> resource group where your firewall policy is currently deployed
                </p>
              </div>
              
              <div className="bg-blue-50 p-4 rounded-md border border-blue-200">
                <h4 className="text-sm font-medium text-blue-900 mb-2">How Draft + Deploy Works:</h4>
                <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
                  <li><strong>Create draft:</strong> Azure CLI creates a temporary copy of your policy</li>
                  <li><strong>Update draft:</strong> Your rule modifications are applied to the draft only</li>
                  <li><strong>Review draft:</strong> Check changes in Azure Portal (draft won't affect live traffic)</li>
                  <li><strong>Deploy draft:</strong> Replace live policy with draft when ready</li>
                </ol>
                <div className="mt-3 p-2 bg-blue-100 rounded text-xs text-blue-700">
                  <strong>Requirements:</strong> Azure CLI with firewall extension v1.2.3+ and proper permissions on your firewall policy
                </div>
              </div>
              
              <div className="flex space-x-3">
                <button
                  onClick={handleExportDraft}
                  className="flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download JSON
                </button>
                
                <button
                  onClick={handleCopyCommands}
                  className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                >
                  <Copy className="w-4 h-4 mr-2" />
                  Copy CLI Commands
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}