import { useState, useCallback } from 'react';
import { Shield, FileText, BarChart3, Globe, AlertTriangle, Edit3 } from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { RuleTable } from './components/RuleTable';
import { RuleMindMap } from './components/RuleVisualization/RuleMindMap';
import { RuleAnalysisPanel } from './components/RuleAnalysisPanel';
import { IssuesView } from './components/IssuesView';
import { RuleEditor } from './components/RuleEditor';
import { FirewallPolicyParser } from './utils/parser';
import { RuleProcessor } from './utils/ruleProcessor';
import { RuleAnalyzer } from './utils/ruleAnalyzer';
import type { 
  FirewallPolicy, 
  ProcessedRuleCollectionGroup, 
  ProcessedRule 
} from './types/firewall.types';
import type { RuleAnalysis } from './utils/ruleAnalyzer';

interface AppState {
  policy: FirewallPolicy | null;
  processedGroups: ProcessedRuleCollectionGroup[];
  selectedRule: ProcessedRule | null;
  isLoading: boolean;
  error: string | null;
  currentView: 'table' | 'mindmap' | 'issues' | 'editor';
  ruleAnalysis: RuleAnalysis | null;
  showAnalysisPanel: boolean;
}

function App() {
  const [state, setState] = useState<AppState>({
    policy: null,
    processedGroups: [],
    selectedRule: null,
    isLoading: false,
    error: null,
    currentView: 'table',
    ruleAnalysis: null,
    showAnalysisPanel: false
  });

  const handleFileUpload = useCallback(async (_file: File, content: string) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      // Parse the firewall policy
      const policy = FirewallPolicyParser.parseFirewallPolicy(content);
      
      // Process rules according to Azure Firewall logic
      const processedGroups = RuleProcessor.processFirewallPolicy(policy);
      
      // Analyze rules for duplicates and conflicts
      const ruleAnalysis = RuleAnalyzer.analyzeRules(processedGroups);

      setState(prev => ({
        ...prev,
        policy,
        processedGroups,
        ruleAnalysis,
        isLoading: false,
        error: null
      }));

      console.log('Parsed policy:', policy);
      console.log('Processed groups:', processedGroups);
      console.log('Policy summary:', FirewallPolicyParser.getPolicySummary(policy));
      console.log('Rule analysis:', ruleAnalysis);
    } catch (error) {
      console.error('Error processing firewall policy:', error);
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }));
    }
  }, []);

  const handleRuleSelect = useCallback((rule: ProcessedRule) => {
    setState(prev => ({ ...prev, selectedRule: rule }));
  }, []);

  const handleRulesChange = useCallback((newGroups: ProcessedRuleCollectionGroup[]) => {
    setState(prev => ({
      ...prev,
      processedGroups: newGroups,
      ruleAnalysis: RuleAnalyzer.analyzeRules(newGroups)
    }));
  }, []);

  const handleViewChange = useCallback((newView: 'table' | 'mindmap' | 'issues' | 'editor') => {
    setState(prev => ({
      ...prev,
      currentView: newView,
      selectedRule: null, // Clear selection when switching views
      showAnalysisPanel: false // Close analysis panel when switching views
    }));
  }, []);

  const getPolicyStats = () => {
    if (!state.policy) return null;
    
    const summary = FirewallPolicyParser.getPolicySummary(state.policy);
    const processingStats = RuleProcessor.getProcessingStatistics(state.processedGroups);
    
    return { ...summary, ...processingStats };
  };

  const stats = getPolicyStats();

  const getDestinationDisplay = useCallback((rule: ProcessedRule | null) => {
    if (!rule) return 'Any';

    if (rule.ruleType === 'ApplicationRule') {
      return rule.targetFqdns?.join('\n') || 'Any';
    }

    if (rule.ruleType === 'NetworkRule') {
      const destinations = [
        ...(rule.destinationAddresses || []),
        ...(rule.destinationFqdns || []),
        ...(rule.destinationIpGroups || []),
      ];

      return destinations.length > 0 ? destinations.join('\n') : 'Any';
    }

    return rule.destinationAddresses?.join('\n') || 'Any';
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <button 
              onClick={() => setState(prev => ({ 
                ...prev, 
                ...(prev.policy ? {
                  // If policy is loaded, just reset view state but keep data
                  selectedRule: null,
                  currentView: 'table',
                  showAnalysisPanel: false
                } : {
                  // If no policy, clear everything (shouldn't happen but safe fallback)
                  policy: null, 
                  processedGroups: [], 
                  selectedRule: null,
                  currentView: 'table',
                  ruleAnalysis: null,
                  showAnalysisPanel: false
                })
              }))}
              className="flex items-center hover:opacity-80 transition-opacity"
            >
              <Shield className="w-8 h-8 text-blue-600 mr-3" />
              <h1 className="text-lg font-semibold text-gray-900 whitespace-nowrap">
                Azure Firewall Analyzer
              </h1>
            </button>
            {stats && (
              <div className="flex items-center space-x-2 text-sm text-gray-600">
                <div className="flex items-center whitespace-nowrap">
                  <BarChart3 className="w-3 h-3 mr-1" />
                  <span>{stats.totalRules} rules</span>
                </div>
                <div className="flex items-center whitespace-nowrap">
                  <FileText className="w-3 h-3 mr-1" />
                  <span>{stats.totalGroups} groups</span>
                </div>
                <div className="flex items-center space-x-2 whitespace-nowrap">
                  <span className="flex items-center">
                    <div className="w-3 h-3 bg-rule-dnat rounded mr-1"></div>
                    DNAT ({stats.rulesByCategory.DNAT})
                  </span>
                  <span className="flex items-center">
                    <div className="w-3 h-3 bg-rule-network rounded mr-1"></div>
                    Network ({stats.rulesByCategory.Network})
                  </span>
                  <span className="flex items-center">
                    <div className="w-3 h-3 bg-rule-application rounded mr-1"></div>
                    Application ({stats.rulesByCategory.Application})
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleViewChange('table')}
                    className={`flex items-center px-2 py-1 rounded-md transition-colors text-sm ${
                      state.currentView === 'table'
                        ? 'bg-blue-200 text-blue-800'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    <FileText className="w-4 h-4 mr-1" />
                    <span className="hidden sm:inline">Table</span>
                  </button>
                  
                  <button
                    onClick={() => handleViewChange('mindmap')}
                    className={`flex items-center px-2 py-1 rounded-md transition-colors text-sm ${
                      state.currentView === 'mindmap'
                        ? 'bg-blue-200 text-blue-800'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    <Globe className="w-4 h-4 mr-1" />
                    <span className="hidden sm:inline">Mind Map</span>
                  </button>
                  
                  <button
                    onClick={() => handleViewChange('editor')}
                    className={`flex items-center px-2 py-1 rounded-md transition-colors text-sm ${
                      state.currentView === 'editor'
                        ? 'bg-green-200 text-green-800'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    }`}
                  >
                    <Edit3 className="w-4 h-4 mr-1" />
                    <span className="hidden sm:inline">Editor</span>
                  </button>
                  
                  {state.ruleAnalysis && (state.ruleAnalysis.duplicates.length > 0 || state.ruleAnalysis.conflicts.length > 0) && (
                    <button
                      onClick={() => handleViewChange('issues')}
                      className={`flex items-center px-2 py-1 rounded-md transition-colors text-sm ${
                        state.currentView === 'issues'
                          ? 'bg-orange-200 text-orange-800'
                          : 'bg-orange-100 text-orange-700 hover:bg-orange-200'
                      }`}
                    >
                      <AlertTriangle className="w-4 h-4 mr-1" />
                      <span className="hidden sm:inline">
                        Issues ({state.ruleAnalysis.duplicates.length + state.ruleAnalysis.conflicts.length})
                      </span>
                      <span className="sm:hidden">({state.ruleAnalysis.duplicates.length + state.ruleAnalysis.conflicts.length})</span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!state.policy ? (
          /* File Upload State */
          <div className="max-w-4xl mx-auto">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                Visualize Your Azure Firewall Rules
              </h2>
              <p className="text-lg text-gray-600 max-w-2xl mx-auto">
                Upload your Azure Firewall Policy JSON export to visualize rule processing order, 
                identify duplicates, and understand your firewall configuration.
              </p>
            </div>

            <FileUpload
              onFileUpload={handleFileUpload}
              isLoading={state.isLoading}
              error={state.error}
            />

            {/* Features */}
            <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center mb-4">
                  <BarChart3 className="w-6 h-6 text-blue-600 mr-2" />
                  <h3 className="font-semibold text-gray-900">Rule Processing Order</h3>
                </div>
                <p className="text-gray-600 text-sm">
                  Visualize the exact order in which Azure Firewall processes your rules, 
                  following priority-based hierarchy.
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center mb-4">
                  <Shield className="w-6 h-6 text-green-600 mr-2" />
                  <h3 className="font-semibold text-gray-900">Duplicate Detection</h3>
                </div>
                <p className="text-gray-600 text-sm">
                  Identify duplicate and overlapping rules that may cause confusion 
                  or unnecessary complexity.
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <div className="flex items-center mb-4">
                  <FileText className="w-6 h-6 text-purple-600 mr-2" />
                  <h3 className="font-semibold text-gray-900">Interactive Visualization</h3>
                </div>
                <p className="text-gray-600 text-sm">
                  Navigate through rule hierarchies with an interactive table and 
                  mindmap visualization.
                </p>
              </div>
            </div>
          </div>
        ) : (
          /* Policy Loaded State */
          <div className="space-y-6">
            {/* Policy Information */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-medium text-gray-900">
                  Policy: {state.policy.name}
                </h2>
                <button
                  onClick={() => setState(prev => ({ 
                    ...prev, 
                    policy: null, 
                    processedGroups: [], 
                    selectedRule: null,
                    currentView: 'table',
                    ruleAnalysis: null,
                    showAnalysisPanel: false
                  }))}
                  className="text-sm text-blue-600 hover:text-blue-800"
                >
                  Upload Different File
                </button>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-gray-500">Location:</span>
                  <div className="font-medium">{state.policy.location}</div>
                </div>
                <div>
                  <span className="text-gray-500">SKU:</span>
                  <div className="font-medium">{state.policy.properties.sku.tier}</div>
                </div>
                <div>
                  <span className="text-gray-500">Threat Intel:</span>
                  <div className="font-medium">{state.policy.properties.threatIntelMode}</div>
                </div>
                <div>
                  <span className="text-gray-500">IDPS:</span>
                  <div className="font-medium">
                    {state.policy.properties.intrusionDetection?.mode || 'Off'}
                  </div>
                </div>
              </div>
            </div>

            {/* Main Content Layout */}
            <div className="flex gap-6 h-[calc(100vh-16rem)]">
              {/* Current View */}
              <div className={`transition-all duration-300 ${
                state.currentView === 'issues'
                  ? (state.selectedRule ? 'w-2/3' : 'w-full')
                  : state.currentView === 'editor'
                    ? 'w-full'
                    : state.showAnalysisPanel 
                      ? (state.selectedRule ? 'w-1/3' : 'w-2/3')
                      : (state.selectedRule ? 'w-2/3' : 'w-full')
              }`}>
                {state.currentView === 'table' ? (
                  <RuleTable
                    groups={state.processedGroups}
                    onRuleSelect={handleRuleSelect}
                    selectedRuleId={state.selectedRule?.id}
                  />
                ) : state.currentView === 'mindmap' ? (
                  <RuleMindMap
                    policyName={state.policy.name}
                    groups={state.processedGroups}
                    onRuleSelect={handleRuleSelect}
                    selectedRuleId={state.selectedRule?.id}
                  />
                ) : state.currentView === 'issues' && state.ruleAnalysis ? (
                  <IssuesView
                    analysis={state.ruleAnalysis}
                    onRuleSelect={handleRuleSelect}
                  />
                ) : state.currentView === 'editor' ? (
                  <RuleEditor
                    groups={state.processedGroups}
                    policyName={state.policy.name}
                    onRulesChange={handleRulesChange}
                  />
                ) : null}
              </div>

              {/* Side Panel for Selected Rule Details in Issues View */}
              {state.selectedRule && state.currentView === 'issues' && (
                <div className="w-1/3 bg-white rounded-lg shadow-sm border border-gray-200 p-6 sticky top-6 h-fit max-h-[calc(100vh-8rem)] overflow-y-auto">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-gray-900">
                      Rule Details
                    </h3>
                    <button
                      onClick={() => setState(prev => ({ ...prev, selectedRule: null }))}
                      className="text-gray-400 hover:text-gray-600 focus:outline-none"
                      title="Close details"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>

                  {/* Rule Name and Order */}
                  <div className="mb-6 p-4 bg-gray-50 rounded-lg">
                    <h4 className="font-semibold text-gray-900 text-lg mb-2">{state.selectedRule.name}</h4>
                    <div className="flex items-center justify-between text-sm">
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        #{state.selectedRule.processingOrder}
                      </span>
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${
                        state.selectedRule.ruleType === 'NatRule' ? 'bg-blue-100 text-blue-800 border-blue-200' :
                        state.selectedRule.ruleType === 'NetworkRule' ? 'bg-green-100 text-green-800 border-green-200' :
                        'bg-yellow-100 text-yellow-800 border-yellow-200'
                      }`}>
                        {state.selectedRule.ruleType.replace('Rule', '')}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-6">
                    {/* Basic Information */}
                    <div>
                      <h4 className="font-medium text-gray-900 mb-3">Basic Information</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-500">Category:</span>
                          <span className="font-medium">{state.selectedRule.ruleCategory}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Collection:</span>
                          <span className="font-medium">{state.selectedRule.collectionName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Group:</span>
                          <span className="font-medium">{state.selectedRule.collectionGroupName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Group Priority:</span>
                          <span className="font-medium">{state.selectedRule.groupPriority}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Collection Priority:</span>
                          <span className="font-medium">{state.selectedRule.collectionPriority}</span>
                        </div>
                      </div>
                    </div>

                    {/* Rule Configuration */}
                    <div>
                      <h4 className="font-medium text-gray-900 mb-3">Configuration</h4>
                      <div className="space-y-3 text-sm">
                        {state.selectedRule.ruleType === 'ApplicationRule' && (
                          <>
                            <div>
                              <span className="text-gray-500 block mb-1">Target FQDNs:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono max-h-32 overflow-y-auto">
                                {state.selectedRule.targetFqdns?.join('\n') || 'None'}
                              </div>
                            </div>
                            <div>
                              <span className="text-gray-500 block mb-1">Protocols:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.protocols?.map((p: any) => `${p.protocolType}:${p.port}`).join(', ') || 'None'}
                              </div>
                            </div>
                          </>
                        )}
                        
                        {state.selectedRule.ruleType === 'NetworkRule' && (
                          <>
                            <div>
                              <span className="text-gray-500 block mb-1">Protocols:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.ipProtocols?.join(', ') || 'None'}
                              </div>
                            </div>
                            <div>
                              <span className="text-gray-500 block mb-1">Destination Ports:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.destinationPorts?.join(', ') || 'None'}
                              </div>
                            </div>
                          </>
                        )}
                        
                        {state.selectedRule.ruleType === 'NatRule' && (
                          <>
                            <div>
                              <span className="text-gray-500 block mb-1">Translation:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.translatedAddress}:{state.selectedRule.translatedPort}
                              </div>
                            </div>
                            <div>
                              <span className="text-gray-500 block mb-1">Protocols:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.ipProtocols?.join(', ') || 'None'}
                              </div>
                            </div>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Source & Destination */}
                    <div>
                      <h4 className="font-medium text-gray-900 mb-3">Source & Destination</h4>
                      <div className="space-y-3 text-sm">
                        <div>
                          <span className="text-gray-500 block mb-1">Source Addresses:</span>
                          <div className="p-2 bg-gray-50 rounded text-xs font-mono max-h-32 overflow-y-auto">
                            {state.selectedRule.sourceAddresses?.join('\n') || 'Any'}
                          </div>
                        </div>
                        <div>
                          <span className="text-gray-500 block mb-1">Destination Addresses:</span>
                          <div className="p-2 bg-gray-50 rounded text-xs font-mono max-h-32 overflow-y-auto">
                            {getDestinationDisplay(state.selectedRule)}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Side Panel for Selected Rule Details in Table/Mindmap Views */}
              {state.selectedRule && !state.showAnalysisPanel && state.currentView !== 'issues' && (
                <div className="w-1/3 bg-white rounded-lg shadow-sm border border-gray-200 p-6 sticky top-6 h-fit max-h-[calc(100vh-8rem)] overflow-y-auto">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-gray-900">
                      Rule Details
                    </h3>
                    <button
                      onClick={() => setState(prev => ({ ...prev, selectedRule: null }))}
                      className="text-gray-400 hover:text-gray-600 focus:outline-none"
                      title="Close details"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>

                  {/* Rule Name and Order */}
                  <div className="mb-6 p-4 bg-gray-50 rounded-lg">
                    <h4 className="font-semibold text-gray-900 text-lg mb-2">{state.selectedRule.name}</h4>
                    <div className="flex items-center justify-between text-sm">
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        #{state.selectedRule.processingOrder}
                      </span>
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${
                        state.selectedRule.ruleType === 'NatRule' ? 'bg-blue-100 text-blue-800 border-blue-200' :
                        state.selectedRule.ruleType === 'NetworkRule' ? 'bg-green-100 text-green-800 border-green-200' :
                        'bg-yellow-100 text-yellow-800 border-yellow-200'
                      }`}>
                        {state.selectedRule.ruleType.replace('Rule', '')}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-6">
                    {/* Basic Information */}
                    <div>
                      <h4 className="font-medium text-gray-900 mb-3">Basic Information</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-500">Category:</span>
                          <span className="font-medium">{state.selectedRule.ruleCategory}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Collection:</span>
                          <span className="font-medium">{state.selectedRule.collectionName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Group:</span>
                          <span className="font-medium">{state.selectedRule.collectionGroupName}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Group Priority:</span>
                          <span className="font-medium">{state.selectedRule.groupPriority}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Collection Priority:</span>
                          <span className="font-medium">{state.selectedRule.collectionPriority}</span>
                        </div>
                      </div>
                    </div>

                    {/* Rule Configuration */}
                    <div>
                      <h4 className="font-medium text-gray-900 mb-3">Configuration</h4>
                      <div className="space-y-3 text-sm">
                        {state.selectedRule.ruleType === 'ApplicationRule' && (
                          <>
                            <div>
                              <span className="text-gray-500 block mb-1">Target FQDNs:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono max-h-32 overflow-y-auto">
                                {state.selectedRule.targetFqdns?.join('\n') || 'None'}
                              </div>
                            </div>
                            <div>
                              <span className="text-gray-500 block mb-1">Protocols:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.protocols?.map((p: any) => `${p.protocolType}:${p.port}`).join(', ') || 'None'}
                              </div>
                            </div>
                          </>
                        )}
                        
                        {state.selectedRule.ruleType === 'NetworkRule' && (
                          <>
                            <div>
                              <span className="text-gray-500 block mb-1">Protocols:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.ipProtocols?.join(', ') || 'None'}
                              </div>
                            </div>
                            <div>
                              <span className="text-gray-500 block mb-1">Destination Ports:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.destinationPorts?.join(', ') || 'None'}
                              </div>
                            </div>
                          </>
                        )}
                        
                        {state.selectedRule.ruleType === 'NatRule' && (
                          <>
                            <div>
                              <span className="text-gray-500 block mb-1">Translation:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.translatedAddress}:{state.selectedRule.translatedPort}
                              </div>
                            </div>
                            <div>
                              <span className="text-gray-500 block mb-1">Protocols:</span>
                              <div className="p-2 bg-gray-50 rounded text-xs font-mono">
                                {state.selectedRule.ipProtocols?.join(', ') || 'None'}
                              </div>
                            </div>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Source & Destination */}
                    <div>
                      <h4 className="font-medium text-gray-900 mb-3">Source & Destination</h4>
                      <div className="space-y-3 text-sm">
                        <div>
                          <span className="text-gray-500 block mb-1">Source Addresses:</span>
                          <div className="p-2 bg-gray-50 rounded text-xs font-mono max-h-32 overflow-y-auto">
                            {state.selectedRule.sourceAddresses?.join('\n') || 'Any'}
                          </div>
                        </div>
                        <div>
                          <span className="text-gray-500 block mb-1">Destination Addresses:</span>
                          <div className="p-2 bg-gray-50 rounded text-xs font-mono max-h-32 overflow-y-auto">
                            {getDestinationDisplay(state.selectedRule)}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Analysis Panel */}
              {state.showAnalysisPanel && state.ruleAnalysis && (
                <RuleAnalysisPanel
                  analysis={state.ruleAnalysis}
                  onClose={() => setState(prev => ({ ...prev, showAnalysisPanel: false }))}
                  onRuleSelect={handleRuleSelect}
                />
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
