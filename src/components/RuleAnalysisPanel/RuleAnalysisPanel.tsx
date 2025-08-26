import React from 'react';
import { AlertTriangle, Copy, X, ExternalLink } from 'lucide-react';
import type { RuleAnalysis, RuleConflict } from '../../utils/ruleAnalyzer';
import type { ProcessedRule } from '../../types/firewall.types';

interface RuleAnalysisPanelProps {
  analysis: RuleAnalysis;
  onClose: () => void;
  onRuleSelect: (rule: ProcessedRule) => void;
}

export const RuleAnalysisPanel: React.FC<RuleAnalysisPanelProps> = ({ 
  analysis, 
  onClose, 
  onRuleSelect 
}) => {
  const getSeverityColor = (severity: RuleConflict['severity']) => {
    switch (severity) {
      case 'high':
        return 'bg-red-50 border-red-200 text-red-800';
      case 'medium':
        return 'bg-orange-50 border-orange-200 text-orange-800';
      case 'low':
        return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      default:
        return 'bg-gray-50 border-gray-200 text-gray-800';
    }
  };

  const getConflictIcon = (conflictType: RuleConflict['conflictType']) => {
    switch (conflictType) {
      case 'allow_deny_conflict':
        return '⚠️';
      case 'priority_conflict':
        return '🔄';
      case 'overlapping_rules':
        return '📝';
      default:
        return '❓';
    }
  };

  return (
    <div className="bg-white border-l border-gray-200 w-1/3 h-full overflow-y-auto">
      {/* Header */}
      <div className="sticky top-0 bg-white border-b border-gray-200 p-4 flex items-center justify-between">
        <div className="flex items-center">
          <AlertTriangle className="w-5 h-5 text-orange-600 mr-2" />
          <h3 className="text-lg font-medium text-gray-900">Rule Analysis</h3>
        </div>
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-gray-600 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Statistics */}
      <div className="p-4 border-b border-gray-200 bg-gray-50">
        <h4 className="text-sm font-medium text-gray-900 mb-2">Analysis Summary</h4>
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="bg-white p-2 rounded border">
            <div className="text-gray-500">Total Rules</div>
            <div className="text-lg font-bold text-gray-900">{analysis.statistics.totalRules}</div>
          </div>
          <div className="bg-white p-2 rounded border">
            <div className="text-gray-500">Duplicate Groups</div>
            <div className="text-lg font-bold text-orange-600">{analysis.statistics.duplicateGroups}</div>
          </div>
          <div className="bg-white p-2 rounded border">
            <div className="text-gray-500">Duplicate Rules</div>
            <div className="text-lg font-bold text-orange-600">{analysis.statistics.duplicateRules}</div>
          </div>
          <div className="bg-white p-2 rounded border">
            <div className="text-gray-500">Conflicts</div>
            <div className="text-lg font-bold text-red-600">{analysis.statistics.conflicts}</div>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Duplicate Rules Section */}
        {analysis.duplicates.length > 0 && (
          <div>
            <div className="flex items-center mb-3">
              <Copy className="w-4 h-4 text-orange-600 mr-2" />
              <h4 className="text-sm font-medium text-gray-900">
                Duplicate Rules ({analysis.duplicates.length} groups)
              </h4>
            </div>
            
            <div className="space-y-3">
              {analysis.duplicates.map((duplicateGroup) => (
                <div
                  key={duplicateGroup.id}
                  className="border border-orange-200 rounded-lg p-3 bg-orange-50"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <div className={`inline-block px-2 py-1 text-xs rounded-full ${
                        duplicateGroup.type === 'exact_duplicate' 
                          ? 'bg-red-100 text-red-800' 
                          : 'bg-orange-100 text-orange-800'
                      }`}>
                        {duplicateGroup.type === 'exact_duplicate' ? 'Exact Duplicate' : 'Similar Rules'}
                      </div>
                    </div>
                  </div>
                  
                  <p className="text-xs text-gray-700 mb-3">{duplicateGroup.description}</p>
                  
                  <div className="space-y-2">
                    <div className="text-xs font-medium text-gray-900">Affected Rules:</div>
                    {duplicateGroup.rules.map((rule) => (
                      <button
                        key={rule.id}
                        onClick={() => onRuleSelect(rule)}
                        className="w-full text-left p-2 bg-white border border-orange-200 rounded hover:bg-orange-50 transition-colors text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="font-medium text-gray-900">{rule.name}</div>
                            <div className="text-gray-500">
                              #{rule.processingOrder} • {rule.collectionName} • {rule.ruleCategory}
                            </div>
                          </div>
                          <ExternalLink className="w-3 h-3 text-gray-400" />
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Rule Conflicts Section */}
        {analysis.conflicts.length > 0 && (
          <div>
            <div className="flex items-center mb-3">
              <AlertTriangle className="w-4 h-4 text-red-600 mr-2" />
              <h4 className="text-sm font-medium text-gray-900">
                Rule Conflicts ({analysis.conflicts.length})
              </h4>
            </div>
            
            <div className="space-y-3">
              {analysis.conflicts.map((conflict) => (
                <div
                  key={conflict.id}
                  className={`border rounded-lg p-3 ${getSeverityColor(conflict.severity)}`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center">
                      <span className="mr-2">{getConflictIcon(conflict.conflictType)}</span>
                      <div className={`inline-block px-2 py-1 text-xs rounded-full border ${
                        conflict.severity === 'high' ? 'bg-red-100 text-red-800 border-red-200' :
                        conflict.severity === 'medium' ? 'bg-orange-100 text-orange-800 border-orange-200' :
                        'bg-yellow-100 text-yellow-800 border-yellow-200'
                      }`}>
                        {conflict.severity.toUpperCase()} SEVERITY
                      </div>
                    </div>
                  </div>
                  
                  <p className="text-xs text-gray-700 mb-3">{conflict.description}</p>
                  
                  <div className="space-y-2">
                    <div className="text-xs font-medium text-gray-900">Conflicting Rules:</div>
                    
                    {/* Primary Rule */}
                    <button
                      onClick={() => onRuleSelect(conflict.rules.primary)}
                      className="w-full text-left p-2 bg-white border rounded hover:bg-gray-50 transition-colors text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium text-gray-900">
                            {conflict.rules.primary.name} (Primary)
                          </div>
                          <div className="text-gray-500">
                            #{conflict.rules.primary.processingOrder} • {conflict.rules.primary.collectionName}
                          </div>
                        </div>
                        <ExternalLink className="w-3 h-3 text-gray-400" />
                      </div>
                    </button>
                    
                    {/* Conflicting Rule */}
                    <button
                      onClick={() => onRuleSelect(conflict.rules.conflicting)}
                      className="w-full text-left p-2 bg-white border rounded hover:bg-gray-50 transition-colors text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="font-medium text-gray-900">
                            {conflict.rules.conflicting.name} (Conflicting)
                          </div>
                          <div className="text-gray-500">
                            #{conflict.rules.conflicting.processingOrder} • {conflict.rules.conflicting.collectionName}
                          </div>
                        </div>
                        <ExternalLink className="w-3 h-3 text-gray-400" />
                      </div>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* No Issues Found */}
        {analysis.duplicates.length === 0 && analysis.conflicts.length === 0 && (
          <div className="text-center py-8">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h4 className="text-sm font-medium text-gray-900 mb-1">No Issues Found</h4>
            <p className="text-xs text-gray-500">
              Your firewall policy appears to be clean with no duplicate rules or conflicts detected.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};