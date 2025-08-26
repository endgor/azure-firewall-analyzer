import React, { useState } from 'react';
import { AlertTriangle, Copy, ExternalLink, CheckCircle, Download, FileSpreadsheet } from 'lucide-react';
import type { RuleAnalysis, RuleConflict } from '../../utils/ruleAnalyzer';
import type { ProcessedRule } from '../../types/firewall.types';
import { exportToCSV, exportToExcel, type ExportData } from '../../utils/exportUtils';

type FilterType = 'all' | 'duplicate-groups' | 'duplicate-rules' | 'conflicts';

interface IssuesViewProps {
  analysis: RuleAnalysis;
  onRuleSelect: (rule: ProcessedRule) => void;
}

export const IssuesView: React.FC<IssuesViewProps> = ({ analysis, onRuleSelect }) => {
  const [filter, setFilter] = useState<FilterType>('all');

  const handleExport = (format: 'csv' | 'excel') => {
    const exportData: ExportData = {
      conflicts: analysis.conflicts,
      duplicates: analysis.duplicates
    };
    
    if (format === 'csv') {
      exportToCSV(exportData, filter);
    } else {
      exportToExcel(exportData, filter);
    }
  };
  const getSeverityColor = (severity: RuleConflict['severity']) => {
    switch (severity) {
      case 'high':
        return 'bg-red-50 border-red-200';
      case 'medium':
        return 'bg-orange-50 border-orange-200';
      case 'low':
        return 'bg-yellow-50 border-yellow-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  const getSeverityTextColor = (severity: RuleConflict['severity']) => {
    switch (severity) {
      case 'high':
        return 'text-red-800';
      case 'medium':
        return 'text-orange-800';
      case 'low':
        return 'text-yellow-800';
      default:
        return 'text-gray-800';
    }
  };

  const getSeverityBadgeColor = (severity: RuleConflict['severity']) => {
    switch (severity) {
      case 'high':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'medium':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'low':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
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

  const hasIssues = analysis.duplicates.length > 0 || analysis.conflicts.length > 0;

  if (!hasIssues) {
    return (
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-8">
        <div className="text-center py-12">
          <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <CheckCircle className="w-10 h-10 text-green-600" />
          </div>
          <h3 className="text-xl font-semibold text-gray-900 mb-2">No Issues Found</h3>
          <p className="text-gray-600 max-w-md mx-auto">
            Your firewall policy appears to be clean with no duplicate rules or conflicts detected.
            This indicates a well-organized and optimized firewall configuration.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200">
      {/* Header */}
      <div className="border-b border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <AlertTriangle className="w-6 h-6 text-orange-600 mr-3" />
            <h2 className="text-xl font-semibold text-gray-900">Rule Analysis Issues</h2>
          </div>
          
          {hasIssues && (
            <div className="flex items-center gap-2">
              <div className="relative group">
                <button
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  onClick={() => {}}
                >
                  <Download className="w-4 h-4" />
                  Export
                </button>
                
                {/* Dropdown menu */}
                <div className="absolute right-0 mt-1 w-40 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                  <button
                    onClick={() => handleExport('csv')}
                    className="w-full flex items-center gap-3 text-left px-4 py-2 hover:bg-gray-50 rounded-t-lg transition-colors"
                  >
                    <FileSpreadsheet className="w-4 h-4 text-blue-600" />
                    <span>Export CSV</span>
                  </button>
                  <button
                    onClick={() => handleExport('excel')}
                    className="w-full flex items-center gap-3 text-left px-4 py-2 hover:bg-gray-50 rounded-b-lg transition-colors"
                  >
                    <FileSpreadsheet className="w-4 h-4 text-green-700" />
                    <span>Export Excel</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Statistics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button
            onClick={() => setFilter('all')}
            className={`p-4 rounded-lg text-center transition-colors ${
              filter === 'all' 
                ? 'bg-blue-100 border-2 border-blue-500' 
                : 'bg-gray-50 hover:bg-gray-100 border-2 border-transparent'
            }`}
          >
            <div className="text-sm text-gray-500">Total Rules</div>
            <div className="text-2xl font-bold text-gray-900">{analysis.statistics.totalRules}</div>
          </button>
          <button
            onClick={() => setFilter('duplicate-groups')}
            className={`p-4 rounded-lg text-center transition-colors ${
              filter === 'duplicate-groups' 
                ? 'bg-orange-100 border-2 border-orange-500' 
                : 'bg-orange-50 hover:bg-orange-100 border-2 border-transparent'
            }`}
          >
            <div className="text-sm text-orange-600">Duplicate Groups</div>
            <div className="text-2xl font-bold text-orange-700">{analysis.statistics.duplicateGroups}</div>
          </button>
          <button
            onClick={() => setFilter('duplicate-rules')}
            className={`p-4 rounded-lg text-center transition-colors ${
              filter === 'duplicate-rules' 
                ? 'bg-orange-100 border-2 border-orange-500' 
                : 'bg-orange-50 hover:bg-orange-100 border-2 border-transparent'
            }`}
          >
            <div className="text-sm text-orange-600">Duplicate Rules</div>
            <div className="text-2xl font-bold text-orange-700">{analysis.statistics.duplicateRules}</div>
          </button>
          <button
            onClick={() => setFilter('conflicts')}
            className={`p-4 rounded-lg text-center transition-colors ${
              filter === 'conflicts' 
                ? 'bg-red-100 border-2 border-red-500' 
                : 'bg-red-50 hover:bg-red-100 border-2 border-transparent'
            }`}
          >
            <div className="text-sm text-red-600">Conflicts</div>
            <div className="text-2xl font-bold text-red-700">{analysis.statistics.conflicts}</div>
          </button>
        </div>
      </div>

      <div className="p-6 space-y-8">
        {/* Duplicate Rules Section */}
        {analysis.duplicates.length > 0 && (filter === 'all' || filter === 'duplicate-groups' || filter === 'duplicate-rules') && (
          <div>
            <div className="flex items-center mb-6">
              <Copy className="w-5 h-5 text-orange-600 mr-3" />
              <h3 className="text-lg font-medium text-gray-900">
                Duplicate Rules ({analysis.duplicates.length} groups)
              </h3>
            </div>
            
            <div className="space-y-4">
              {analysis.duplicates.map((duplicateGroup) => (
                <div
                  key={duplicateGroup.id}
                  className="border border-orange-200 rounded-lg p-6 bg-orange-50"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className={`inline-block px-3 py-1 text-sm font-medium rounded-full ${
                        duplicateGroup.type === 'exact_duplicate' 
                          ? 'bg-red-100 text-red-800 border border-red-200' 
                          : 'bg-orange-100 text-orange-800 border border-orange-200'
                      }`}>
                        {duplicateGroup.type === 'exact_duplicate' ? 'Exact Duplicate' : 'Similar Rules'}
                      </div>
                    </div>
                  </div>
                  
                  <p className="text-gray-700 mb-4 leading-relaxed">{duplicateGroup.description}</p>
                  
                  <div className="space-y-3">
                    <div className="text-sm font-medium text-gray-900 mb-3">Affected Rules ({duplicateGroup.rules.length}):</div>
                    <div className="grid gap-3">
                      {duplicateGroup.rules.map((rule) => (
                        <button
                          key={rule.id}
                          onClick={() => onRuleSelect(rule)}
                          className="w-full text-left p-4 bg-white border border-orange-200 rounded-lg hover:bg-orange-50 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <div className="font-medium text-gray-900 mb-1">{rule.name}</div>
                              <div className="text-sm text-gray-500 mb-2">
                                Processing Order #{rule.processingOrder} • {rule.ruleCategory} Rule
                              </div>
                              <div className="text-xs text-gray-500">
                                Collection: {rule.collectionName} • Group: {rule.collectionGroupName}
                              </div>
                            </div>
                            <ExternalLink className="w-4 h-4 text-gray-400 flex-shrink-0" />
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Rule Conflicts Section */}
        {analysis.conflicts.length > 0 && (filter === 'all' || filter === 'conflicts') && (
          <div>
            <div className="flex items-center mb-6">
              <AlertTriangle className="w-5 h-5 text-red-600 mr-3" />
              <h3 className="text-lg font-medium text-gray-900">
                Rule Conflicts ({analysis.conflicts.length})
              </h3>
            </div>
            
            <div className="space-y-4">
              {analysis.conflicts.map((conflict) => (
                <div
                  key={conflict.id}
                  className={`border rounded-lg p-6 ${getSeverityColor(conflict.severity)}`}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <span className="text-2xl">{getConflictIcon(conflict.conflictType)}</span>
                      <div>
                        <div className={`inline-block px-3 py-1 text-sm font-medium rounded-full border ${getSeverityBadgeColor(conflict.severity)}`}>
                          {conflict.severity.toUpperCase()} SEVERITY
                        </div>
                        <div className={`text-sm mt-1 ${getSeverityTextColor(conflict.severity)}`}>
                          {conflict.conflictType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <p className={`mb-6 leading-relaxed ${getSeverityTextColor(conflict.severity)}`}>
                    {conflict.description}
                  </p>
                  
                  <div className="space-y-3">
                    <div className="text-sm font-medium text-gray-900 mb-3">Conflicting Rules:</div>
                    <div className="grid md:grid-cols-2 gap-4">
                      {/* Primary Rule */}
                      <button
                        onClick={() => onRuleSelect(conflict.rules.primary)}
                        className="text-left p-4 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="inline-block px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">
                            Primary Rule
                          </div>
                          <ExternalLink className="w-3 h-3 text-gray-400" />
                        </div>
                        <div className="font-medium text-gray-900 mb-1">
                          {conflict.rules.primary.name}
                        </div>
                        <div className="text-sm text-gray-500 mb-2">
                          Processing Order #{conflict.rules.primary.processingOrder} • {conflict.rules.primary.ruleCategory} Rule
                        </div>
                        <div className="text-xs text-gray-500">
                          {conflict.rules.primary.collectionName}
                        </div>
                      </button>
                      
                      {/* Conflicting Rule */}
                      <button
                        onClick={() => onRuleSelect(conflict.rules.conflicting)}
                        className="text-left p-4 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="inline-block px-2 py-1 text-xs bg-red-100 text-red-800 rounded">
                            Conflicting Rule
                          </div>
                          <ExternalLink className="w-3 h-3 text-gray-400" />
                        </div>
                        <div className="font-medium text-gray-900 mb-1">
                          {conflict.rules.conflicting.name}
                        </div>
                        <div className="text-sm text-gray-500 mb-2">
                          Processing Order #{conflict.rules.conflicting.processingOrder} • {conflict.rules.conflicting.ruleCategory} Rule
                        </div>
                        <div className="text-xs text-gray-500">
                          {conflict.rules.conflicting.collectionName}
                        </div>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};