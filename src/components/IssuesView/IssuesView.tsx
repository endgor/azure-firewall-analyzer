import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Copy,
  ExternalLink,
  CheckCircle,
  Download,
  FileSpreadsheet,
  ChevronDown
} from 'lucide-react';
import type { RuleAnalysis, RuleConflict } from '../../utils/ruleAnalyzer';
import type { ProcessedRule } from '../../types/firewall.types';
import { exportToCSV, exportToExcel, type ExportData } from '../../utils/exportUtils';

type FilterType = 'all' | 'duplicate-groups' | 'duplicate-rules' | 'conflicts';

interface IssuesViewProps {
  analysis: RuleAnalysis;
  onRuleSelect: (rule: ProcessedRule) => void;
}

const conflictTypeLabels: Record<RuleConflict['conflictType'], string> = {
  allow_deny_conflict: 'Allow vs Deny',
  priority_conflict: 'Priority Order',
  overlapping_rules: 'Overlapping Pattern'
};

const severityStyles: Record<RuleConflict['severity'], {
  badge: string;
  text: string;
  icon: string;
  border: string;
  softBg: string;
}> = {
  high: {
    badge: 'bg-red-100 text-red-700 border border-red-200',
    text: 'text-red-700',
    icon: 'bg-red-100 text-red-600',
    border: 'border-red-200',
    softBg: 'bg-red-50'
  },
  medium: {
    badge: 'bg-orange-100 text-orange-700 border border-orange-200',
    text: 'text-orange-700',
    icon: 'bg-orange-100 text-orange-600',
    border: 'border-orange-200',
    softBg: 'bg-orange-50'
  },
  low: {
    badge: 'bg-yellow-100 text-yellow-700 border border-yellow-200',
    text: 'text-yellow-700',
    icon: 'bg-yellow-100 text-yellow-600',
    border: 'border-yellow-200',
    softBg: 'bg-yellow-50'
  }
};

const duplicateStyles = {
  exact_duplicate: {
    badge: 'bg-red-100 text-red-700 border border-red-200',
    icon: 'bg-red-100 text-red-600',
    border: 'border-red-200',
    softBg: 'bg-red-50'
  },
  similar_rules: {
    badge: 'bg-orange-100 text-orange-700 border border-orange-200',
    icon: 'bg-orange-100 text-orange-600',
    border: 'border-orange-200',
    softBg: 'bg-orange-50'
  }
};

const formatRuleNames = (rules: ProcessedRule[]): string => {
  if (rules.length <= 2) {
    return rules.map(rule => rule.name).join(', ');
  }
  return `${rules[0].name}, ${rules[1].name} +${rules.length - 2} more`;
};

export const IssuesView: React.FC<IssuesViewProps> = ({ analysis, onRuleSelect }) => {
  const [filter, setFilter] = useState<FilterType>('all');
  const [expandedIssues, setExpandedIssues] = useState<string[]>([]);
  const exactDuplicateGroups = useMemo(
    () => analysis.duplicates.filter(group => group.type === 'exact_duplicate'),
    [analysis.duplicates]
  );
  const exactDuplicateRuleCount = useMemo(
    () => exactDuplicateGroups.reduce((sum, group) => sum + group.rules.length, 0),
    [exactDuplicateGroups]
  );

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

  const toggleIssue = (issueId: string) => {
    setExpandedIssues(prev =>
      prev.includes(issueId)
        ? prev.filter(id => id !== issueId)
        : [...prev, issueId]
    );
  };

  const duplicatesToShow = useMemo(() => {
    if (filter === 'duplicate-rules') {
      return exactDuplicateGroups;
    }
    if (filter === 'duplicate-groups' || filter === 'all') {
      return analysis.duplicates;
    }
    return [];
  }, [analysis.duplicates, exactDuplicateGroups, filter]);

  const conflictsToShow = useMemo(() => {
    if (filter === 'conflicts' || filter === 'all') {
      return analysis.conflicts;
    }
    return [];
  }, [analysis.conflicts, filter]);

  const hasIssues = analysis.duplicates.length > 0 || analysis.conflicts.length > 0;
  const showingDuplicates = duplicatesToShow.length > 0;
  const showingConflicts = conflictsToShow.length > 0;

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

  const nothingToShow = filter !== 'all' && !showingDuplicates && !showingConflicts;

  return (
    <div className="flex h-full flex-col rounded-lg border border-gray-200 bg-white shadow-sm">
      <div className="border-b border-gray-200 p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-orange-600" />
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Rule Analysis Issues</h2>
              <p className="text-xs text-gray-500">Review duplicates and conflicts detected for the uploaded policy.</p>
            </div>
          </div>

          <div className="relative group">
            <button
              className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700"
              onClick={() => {}}
            >
              <Download className="w-4 h-4" />
              Export
            </button>
            <div className="invisible absolute right-0 mt-1 w-40 rounded-lg border border-gray-200 bg-white shadow-lg opacity-0 transition-all duration-200 group-hover:visible group-hover:opacity-100">
              <button
                onClick={() => handleExport('csv')}
                className="flex w-full items-center gap-3 rounded-t-lg px-4 py-2 text-left text-sm text-gray-700 transition-colors hover:bg-gray-50"
              >
                <FileSpreadsheet className="w-4 h-4 text-blue-600" />
                Export CSV
              </button>
              <button
                onClick={() => handleExport('excel')}
                className="flex w-full items-center gap-3 rounded-b-lg px-4 py-2 text-left text-sm text-gray-700 transition-colors hover:bg-gray-50"
              >
                <FileSpreadsheet className="w-4 h-4 text-green-700" />
                Export Excel
              </button>
            </div>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <button
            onClick={() => setFilter('all')}
            className={`rounded-lg border px-4 py-3 text-left transition-colors ${
              filter === 'all'
                ? 'border-blue-500 bg-blue-50'
                : 'border-transparent bg-gray-50 hover:bg-gray-100'
            }`}
          >
            <div className="text-xs uppercase tracking-wide text-gray-500">Total Rules</div>
            <div className="text-xl font-semibold text-gray-900">{analysis.statistics.totalRules}</div>
          </button>
          <button
            onClick={() => setFilter('duplicate-groups')}
            className={`rounded-lg border px-4 py-3 text-left transition-colors ${
              filter === 'duplicate-groups'
                ? 'border-orange-500 bg-orange-50'
                : 'border-transparent bg-gray-50 hover:bg-gray-100'
            }`}
          >
            <div className="text-xs uppercase tracking-wide text-orange-600">Duplicate Groups</div>
            <div className="text-xl font-semibold text-orange-700">{analysis.statistics.duplicateGroups}</div>
          </button>
          <button
            onClick={() => setFilter('duplicate-rules')}
            className={`rounded-lg border px-4 py-3 text-left transition-colors ${
              filter === 'duplicate-rules'
                ? 'border-orange-500 bg-orange-50'
                : 'border-transparent bg-gray-50 hover:bg-gray-100'
            }`}
          >
            <div className="text-xs uppercase tracking-wide text-orange-600">Exact Duplicates</div>
            <div className="text-xl font-semibold text-orange-700">{exactDuplicateRuleCount}</div>
          </button>
          <button
            onClick={() => setFilter('conflicts')}
            className={`rounded-lg border px-4 py-3 text-left transition-colors ${
              filter === 'conflicts'
                ? 'border-red-500 bg-red-50'
                : 'border-transparent bg-gray-50 hover:bg-gray-100'
            }`}
          >
            <div className="text-xs uppercase tracking-wide text-red-600">Conflicts</div>
            <div className="text-xl font-semibold text-red-700">{analysis.statistics.conflicts}</div>
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="space-y-8 px-6 py-6">
          {showingDuplicates && (
            <section>
              <div className="mb-3 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-medium text-gray-900">
                  <Copy className="h-4 w-4 text-orange-600" />
                  Duplicate Rules ({duplicatesToShow.length})
                </div>
                <span className="text-xs text-gray-500">
                  Click a row to reveal impacted rules
                </span>
              </div>

              <div className="space-y-2">
                {duplicatesToShow.map(duplicateGroup => {
                  const issueId = `duplicate-${duplicateGroup.id}`;
                  const isExpanded = expandedIssues.includes(issueId);
                  const styles = duplicateStyles[duplicateGroup.type];

                  return (
                    <div
                      key={duplicateGroup.id}
                      className={`rounded-lg border ${styles.border} ${isExpanded ? 'bg-white' : styles.softBg} transition-colors`}
                    >
                      <button
                        onClick={() => toggleIssue(issueId)}
                        className="flex w-full items-start gap-3 px-4 py-3 text-left"
                      >
                        <div className={`flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full ${styles.icon}`}>
                          <Copy className="h-4 w-4" />
                        </div>
                        <div className="flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${styles.badge}`}>
                              {duplicateGroup.type === 'exact_duplicate' ? 'Exact duplicate' : 'Similar traffic pattern'}
                            </span>
                            <span className="text-xs text-gray-500">{duplicateGroup.rules.length} rule{duplicateGroup.rules.length === 1 ? '' : 's'}</span>
                          </div>
                          <div className="mt-1 text-sm font-semibold text-gray-900">
                            {formatRuleNames(duplicateGroup.rules)}
                          </div>
                          <div className="mt-1 text-xs text-gray-600">
                            {duplicateGroup.description}
                          </div>
                        </div>
                        <ChevronDown
                          className={`mt-1 h-4 w-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                        />
                      </button>

                      {isExpanded && (
                        <div className="space-y-2 border-t border-gray-100 bg-white px-4 py-3">
                          {duplicateGroup.rules.map(rule => (
                            <button
                              key={rule.id}
                              onClick={() => onRuleSelect(rule)}
                              className="flex w-full items-center justify-between gap-3 rounded-md border border-orange-100 bg-orange-50 px-3 py-2 text-left text-xs transition-colors hover:border-orange-200 hover:bg-white"
                            >
                              <div>
                                <div className="text-sm font-medium text-gray-900">{rule.name}</div>
                                <div className="mt-0.5 text-[11px] uppercase tracking-wide text-gray-500">
                                  #{rule.processingOrder} • {rule.collectionName} • {rule.ruleCategory}
                                </div>
                                <div className="mt-0.5 text-[11px] text-gray-500">
                                  Group: {rule.collectionGroupName}
                                </div>
                              </div>
                              <ExternalLink className="h-3 w-3 flex-shrink-0 text-gray-400" />
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {showingConflicts && (
            <section>
              <div className="mb-3 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-medium text-gray-900">
                  <AlertTriangle className="h-4 w-4 text-red-600" />
                  Rule Conflicts ({conflictsToShow.length})
                </div>
                <span className="text-xs text-gray-500">
                  Expand a row to review both rules side by side
                </span>
              </div>

              <div className="space-y-2">
                {conflictsToShow.map(conflict => {
                  const issueId = `conflict-${conflict.id}`;
                  const isExpanded = expandedIssues.includes(issueId);
                  const styles = severityStyles[conflict.severity];

                  return (
                    <div
                      key={conflict.id}
                      className={`rounded-lg border ${styles.border} ${isExpanded ? 'bg-white' : styles.softBg} transition-colors`}
                    >
                      <button
                        onClick={() => toggleIssue(issueId)}
                        className="flex w-full items-start gap-3 px-4 py-3 text-left"
                      >
                        <div className={`flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full ${styles.icon}`}>
                          <AlertTriangle className="h-4 w-4" />
                        </div>
                        <div className="flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${styles.badge}`}>
                              {conflict.severity.toUpperCase()} severity
                            </span>
                            <span className="text-xs text-gray-500">{conflictTypeLabels[conflict.conflictType]}</span>
                          </div>
                          <div className="mt-1 text-sm font-semibold text-gray-900">
                            {conflict.rules.primary.name} ↔ {conflict.rules.conflicting.name}
                          </div>
                          <div className={`mt-1 text-xs ${styles.text}`}>
                            {conflict.description}
                          </div>
                        </div>
                        <ChevronDown
                          className={`mt-1 h-4 w-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                        />
                      </button>

                      {isExpanded && (
                        <div className="space-y-3 border-t border-gray-100 bg-white px-4 py-4">
                          <div className="grid gap-3 md:grid-cols-2">
                            <button
                              onClick={() => onRuleSelect(conflict.rules.primary)}
                              className="flex w-full flex-col gap-1 rounded-md border border-gray-200 bg-gray-50 px-3 py-2 text-left text-xs transition-colors hover:border-gray-300 hover:bg-white"
                            >
                              <div className="flex items-center justify-between">
                                <span className="rounded px-2 py-0.5 text-[11px] font-medium text-blue-700">Primary</span>
                                <ExternalLink className="h-3 w-3 text-gray-400" />
                              </div>
                              <div className="text-sm font-medium text-gray-900">{conflict.rules.primary.name}</div>
                              <div className="text-[11px] text-gray-500">
                                #{conflict.rules.primary.processingOrder} • {conflict.rules.primary.ruleCategory}
                              </div>
                              <div className="text-[11px] text-gray-500">{conflict.rules.primary.collectionName}</div>
                            </button>

                            <button
                              onClick={() => onRuleSelect(conflict.rules.conflicting)}
                              className="flex w-full flex-col gap-1 rounded-md border border-gray-200 bg-gray-50 px-3 py-2 text-left text-xs transition-colors hover:border-gray-300 hover:bg-white"
                            >
                              <div className="flex items-center justify-between">
                                <span className="rounded px-2 py-0.5 text-[11px] font-medium text-red-700">Conflicting</span>
                                <ExternalLink className="h-3 w-3 text-gray-400" />
                              </div>
                              <div className="text-sm font-medium text-gray-900">{conflict.rules.conflicting.name}</div>
                              <div className="text-[11px] text-gray-500">
                                #{conflict.rules.conflicting.processingOrder} • {conflict.rules.conflicting.ruleCategory}
                              </div>
                              <div className="text-[11px] text-gray-500">{conflict.rules.conflicting.collectionName}</div>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {nothingToShow && (
            <div className="rounded-lg border border-dashed border-gray-300 bg-gray-50 px-6 py-10 text-center text-sm text-gray-600">
              No items match this filter yet. Try switching to a different view.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
