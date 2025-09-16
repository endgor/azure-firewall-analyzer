import * as XLSX from 'xlsx';
import type { RuleConflict, DuplicateGroup } from './ruleAnalyzer';
import type { ProcessedRule } from '../types/firewall.types';

export interface ExportData {
  conflicts: RuleConflict[];
  duplicates: DuplicateGroup[];
}

interface ConflictExportRow {
  'Conflict ID': string;
  'Conflict Type': string;
  'Severity': string;
  'Description': string;
  'Primary Rule Name': string;
  'Primary Rule Collection': string;
  'Primary Rule Group': string;
  'Primary Rule Priority': number;
  'Primary Rule Action': string;
  'Primary Rule Source': string;
  'Primary Rule Destination': string;
  'Primary Rule Ports': string;
  'Primary Rule Protocols': string;
  'Conflicting Rule Name': string;
  'Conflicting Rule Collection': string;
  'Conflicting Rule Group': string;
  'Conflicting Rule Priority': number;
  'Conflicting Rule Action': string;
  'Conflicting Rule Source': string;
  'Conflicting Rule Destination': string;
  'Conflicting Rule Ports': string;
  'Conflicting Rule Protocols': string;
  'Recommended Action': string;
}

interface DuplicateExportRow {
  'Duplicate Group ID': string;
  'Duplicate Type': string;
  'Description': string;
  'Rule Name': string;
  'Rule Collection': string;
  'Rule Group': string;
  'Rule Priority': number;
  'Rule Action': string;
  'Rule Source': string;
  'Rule Destination': string;
  'Rule Ports': string;
  'Rule Protocols': string;
  'Recommended Action': string;
}

function getRecommendedAction(conflict: RuleConflict): string {
  switch (conflict.conflictType) {
    case 'allow_deny_conflict':
      return `Review rule precedence. Consider reordering or consolidating rules to avoid Allow/Deny conflicts.`;
    case 'priority_conflict':
      return `Adjust processing order. Higher priority rule (lower number) should be more specific.`;
    case 'overlapping_rules':
      return `Consolidate overlapping rules or ensure proper ordering to prevent unintended behavior.`;
    default:
      return 'Review configuration and resolve conflict based on business requirements.';
  }
}

function getDuplicateRecommendedAction(duplicateGroup: DuplicateGroup): string {
  if (duplicateGroup.type === 'exact_duplicate') {
    return 'Remove duplicate rules to optimize policy and improve performance.';
  }
  return 'Review similar rules and consider consolidating them for better maintainability.';
}

function formatRuleFields(rule: ProcessedRule) {
  const getSourceAddresses = () => {
    if (rule.ruleType === 'NetworkRule') {
      return rule.sourceAddresses?.join(', ') || '';
    }
    if (rule.ruleType === 'ApplicationRule') {
      return rule.sourceAddresses?.join(', ') || '';
    }
    return '';
  };

  const getDestinationAddresses = () => {
    if (rule.ruleType === 'NetworkRule') {
      const destinations = [
        ...(rule.destinationAddresses || []),
        ...(rule.destinationFqdns || []),
      ];
      return destinations.join(', ');
    }
    if (rule.ruleType === 'ApplicationRule') {
      return rule.targetFqdns?.join(', ') || '';
    }
    return '';
  };

  const getPorts = () => {
    if (rule.ruleType === 'NetworkRule') {
      return rule.destinationPorts?.join(', ') || '';
    }
    if (rule.ruleType === 'ApplicationRule') {
      return rule.protocols?.map(p => `${p.protocolType}:${p.port}`).join(', ') || '';
    }
    return '';
  };

  const getProtocols = () => {
    if (rule.ruleType === 'NetworkRule') {
      return rule.ipProtocols?.join(', ') || '';
    }
    if (rule.ruleType === 'ApplicationRule') {
      return rule.protocols?.map(p => p.protocolType).join(', ') || '';
    }
    return '';
  };

  return {
    source: getSourceAddresses(),
    destination: getDestinationAddresses(),
    ports: getPorts(),
    protocols: getProtocols()
  };
}

function convertConflictsToExportData(conflicts: RuleConflict[]): ConflictExportRow[] {
  return conflicts.map(conflict => {
    const primaryFields = formatRuleFields(conflict.rules.primary);
    const conflictingFields = formatRuleFields(conflict.rules.conflicting);

    return {
      'Conflict ID': conflict.id,
      'Conflict Type': conflict.conflictType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      'Severity': conflict.severity.toUpperCase(),
      'Description': conflict.description,
      'Primary Rule Name': conflict.rules.primary.name,
      'Primary Rule Collection': conflict.rules.primary.collectionName,
      'Primary Rule Group': conflict.rules.primary.collectionGroupName,
      'Primary Rule Priority': conflict.rules.primary.processingOrder,
      'Primary Rule Action': conflict.rules.primary.ruleType,
      'Primary Rule Source': primaryFields.source,
      'Primary Rule Destination': primaryFields.destination,
      'Primary Rule Ports': primaryFields.ports,
      'Primary Rule Protocols': primaryFields.protocols,
      'Conflicting Rule Name': conflict.rules.conflicting.name,
      'Conflicting Rule Collection': conflict.rules.conflicting.collectionName,
      'Conflicting Rule Group': conflict.rules.conflicting.collectionGroupName,
      'Conflicting Rule Priority': conflict.rules.conflicting.processingOrder,
      'Conflicting Rule Action': conflict.rules.conflicting.ruleType,
      'Conflicting Rule Source': conflictingFields.source,
      'Conflicting Rule Destination': conflictingFields.destination,
      'Conflicting Rule Ports': conflictingFields.ports,
      'Conflicting Rule Protocols': conflictingFields.protocols,
      'Recommended Action': getRecommendedAction(conflict)
    };
  });
}

function convertDuplicatesToExportData(duplicates: DuplicateGroup[]): DuplicateExportRow[] {
  const rows: DuplicateExportRow[] = [];
  
  duplicates.forEach(duplicateGroup => {
    duplicateGroup.rules.forEach(rule => {
      const fields = formatRuleFields(rule);
      
      rows.push({
        'Duplicate Group ID': duplicateGroup.id,
        'Duplicate Type': duplicateGroup.type === 'exact_duplicate' ? 'Exact Duplicate' : 'Similar Rules',
        'Description': duplicateGroup.description,
        'Rule Name': rule.name,
        'Rule Collection': rule.collectionName,
        'Rule Group': rule.collectionGroupName,
        'Rule Priority': rule.processingOrder,
        'Rule Action': rule.ruleType,
        'Rule Source': fields.source,
        'Rule Destination': fields.destination,
        'Rule Ports': fields.ports,
        'Rule Protocols': fields.protocols,
        'Recommended Action': getDuplicateRecommendedAction(duplicateGroup)
      });
    });
  });
  
  return rows;
}

export function exportToCSV(data: ExportData, filterType: string): void {
  let csvContent = '';
  const timestamp = new Date().toISOString().split('T')[0];
  
  if (filterType === 'all' || filterType === 'conflicts') {
    if (data.conflicts.length > 0) {
      csvContent += 'RULE CONFLICTS\n\n';
      const conflictRows = convertConflictsToExportData(data.conflicts);
      
      // Headers
      const headers = Object.keys(conflictRows[0]);
      csvContent += headers.join(',') + '\n';
      
      // Data rows
      conflictRows.forEach(row => {
        const values = headers.map(header => {
          const value = row[header as keyof ConflictExportRow];
          // Escape CSV special characters
          return typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))
            ? `"${value.replace(/"/g, '""')}"` 
            : String(value);
        });
        csvContent += values.join(',') + '\n';
      });
      
      csvContent += '\n\n';
    }
  }
  
  if (filterType === 'all' || filterType === 'duplicate-groups' || filterType === 'duplicate-rules') {
    if (data.duplicates.length > 0) {
      csvContent += 'DUPLICATE RULES\n\n';
      const duplicateRows = convertDuplicatesToExportData(data.duplicates);
      
      // Headers
      const headers = Object.keys(duplicateRows[0]);
      csvContent += headers.join(',') + '\n';
      
      // Data rows
      duplicateRows.forEach(row => {
        const values = headers.map(header => {
          const value = row[header as keyof DuplicateExportRow];
          // Escape CSV special characters
          return typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))
            ? `"${value.replace(/"/g, '""')}"` 
            : String(value);
        });
        csvContent += values.join(',') + '\n';
      });
    }
  }
  
  // Download CSV
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `firewall-issues-${filterType}-${timestamp}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

export function exportToExcel(data: ExportData, filterType: string): void {
  const workbook = XLSX.utils.book_new();
  const timestamp = new Date().toISOString().split('T')[0];
  
  if (filterType === 'all' || filterType === 'conflicts') {
    if (data.conflicts.length > 0) {
      const conflictRows = convertConflictsToExportData(data.conflicts);
      const conflictsWorksheet = XLSX.utils.json_to_sheet(conflictRows);
      
      // Auto-size columns
      const conflictsRange = XLSX.utils.decode_range(conflictsWorksheet['!ref'] || 'A1');
      const columnWidths = [];
      for (let C = conflictsRange.s.c; C <= conflictsRange.e.c; ++C) {
        let maxWidth = 10;
        for (let R = conflictsRange.s.r; R <= conflictsRange.e.r; ++R) {
          const cellRef = XLSX.utils.encode_cell({ r: R, c: C });
          const cell = conflictsWorksheet[cellRef];
          if (cell && cell.v) {
            maxWidth = Math.max(maxWidth, String(cell.v).length);
          }
        }
        columnWidths.push({ width: Math.min(maxWidth + 2, 50) });
      }
      conflictsWorksheet['!cols'] = columnWidths;
      
      XLSX.utils.book_append_sheet(workbook, conflictsWorksheet, 'Rule Conflicts');
    }
  }
  
  if (filterType === 'all' || filterType === 'duplicate-groups' || filterType === 'duplicate-rules') {
    if (data.duplicates.length > 0) {
      const duplicateRows = convertDuplicatesToExportData(data.duplicates);
      const duplicatesWorksheet = XLSX.utils.json_to_sheet(duplicateRows);
      
      // Auto-size columns
      const duplicatesRange = XLSX.utils.decode_range(duplicatesWorksheet['!ref'] || 'A1');
      const columnWidths = [];
      for (let C = duplicatesRange.s.c; C <= duplicatesRange.e.c; ++C) {
        let maxWidth = 10;
        for (let R = duplicatesRange.s.r; R <= duplicatesRange.e.r; ++R) {
          const cellRef = XLSX.utils.encode_cell({ r: R, c: C });
          const cell = duplicatesWorksheet[cellRef];
          if (cell && cell.v) {
            maxWidth = Math.max(maxWidth, String(cell.v).length);
          }
        }
        columnWidths.push({ width: Math.min(maxWidth + 2, 50) });
      }
      duplicatesWorksheet['!cols'] = columnWidths;
      
      XLSX.utils.book_append_sheet(workbook, duplicatesWorksheet, 'Duplicate Rules');
    }
  }
  
  // Download Excel file
  const excelBuffer = XLSX.write(workbook, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([excelBuffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `firewall-issues-${filterType}-${timestamp}.xlsx`;
  link.click();
  URL.revokeObjectURL(link.href);
}
