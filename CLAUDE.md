# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Azure Firewall Analyzer is a React-based web application for visualizing and analyzing Azure Firewall policies. It parses Azure Firewall Policy JSON exports, processes rules according to Azure's priority logic, and provides interactive visualization with duplicate detection and conflict analysis.

## Development Commands

### Core Commands
- `npm run dev` - Start Vite development server (port 5173)
- `npm run build` - Build production bundle (TypeScript compilation + Vite build)
- `npm run preview` - Preview production build locally
- `npm run lint` - Run ESLint on the codebase

### Docker Commands
- `docker-compose up --build` - Run production build in Docker (port 3000)
- `docker-compose --profile dev up azure-firewall-analyzer-dev` - Run development server in Docker with hot reload (port 5173)
- `docker-compose down` - Stop and remove containers

### Build Requirements
- Always run TypeScript compilation before Vite build (handled by build script)
- Production Docker build uses Node 20 Alpine with Nginx for serving
- Code changes require Docker rebuild unless using development profile

## Architecture Overview

### Core Processing Pipeline
The application follows a 3-stage processing pipeline that mirrors Azure Firewall's actual rule processing logic:

1. **Parsing Stage** (`FirewallPolicyParser`)
   - Parses Azure ARM template JSON exports
   - Extracts nested rule collection groups, collections, and individual rules
   - Normalizes complex Azure resource structure into typed interfaces

2. **Processing Stage** (`RuleProcessor`) 
   - Implements Azure Firewall's exact priority logic:
     - Rule Collection Groups by priority (100 = highest, 65000 = lowest)
     - Within groups: DNAT → Network → Application rules (in that order)
     - Within rule types: Rule Collections by priority
     - Rules processed sequentially within collections
   - Assigns global processing order numbers to all rules
   - Handles parent/child policy inheritance (parent always wins)

3. **Analysis Stage** (`RuleAnalyzer`)
   - Generates rule fingerprints for duplicate detection
   - Identifies conflicting rules (allow/deny conflicts, overlapping rules)
   - Provides optimization suggestions

### State Management
Uses React state with reducer pattern via `useState` in main App component. Key state includes:
- `policy`: Raw parsed Azure Firewall Policy
- `processedGroups`: Rules processed with Azure priority logic applied  
- `ruleAnalysis`: Duplicate and conflict analysis results
- `selectedRule`: Currently selected rule for detail view
- `currentView`: Active view mode ('table' | 'mindmap' | 'issues')

### Component Architecture

#### Core Views
- **RuleTable**: Hierarchical tree view of all rules with search/filter
- **RuleMindMap**: Interactive node-based visualization using ReactFlow
- **IssuesView**: Dedicated view for duplicates and conflicts
- **RuleAnalysisPanel**: Side panel for detailed rule analysis

#### Utilities
- **utils/parser.ts**: Parses Azure ARM template JSON structure
- **utils/ruleProcessor.ts**: Implements Azure Firewall rule processing order
- **utils/ruleAnalyzer.ts**: Detects duplicates, conflicts, and optimization opportunities
- **utils/exportUtils.ts**: Export functionality for processed rule data

### Data Flow
1. User uploads Azure Firewall Policy JSON export
2. `FirewallPolicyParser.parseFirewallPolicy()` extracts rules
3. `RuleProcessor.processFirewallPolicy()` applies Azure priority logic
4. `RuleAnalyzer.analyzeRules()` detects issues and optimizations
5. UI renders processed data in table, mindmap, or issues view

## Key Technical Details

### Azure Firewall Rule Processing Logic
The application implements the exact rule processing order used by Azure Firewall:
- **Threat Intelligence**: Always processed first (if enabled)
- **Rule Collection Groups**: Processed by priority (lower number = higher priority)
- **Parent Policy Precedence**: Parent policy rules always processed before child policy
- **Rule Type Order**: DNAT rules → Network rules → Application rules
- **First Match Wins**: Processing stops at first matching rule within each category

### TypeScript Architecture
- Comprehensive type definitions in `src/types/firewall.types.ts`
- Strict typing for all Azure Firewall resource structures
- Processed rule types extend base Azure types with metadata (processing order, hierarchy info)
- Analysis types for duplicates, conflicts, and optimization suggestions

### Performance Considerations
- Large rule sets (1000+ rules) are handled efficiently
- Virtual scrolling may be needed for very large policies
- React Flow mindmap has built-in performance optimizations for large node graphs
- Analysis algorithms use fingerprinting for O(n) duplicate detection

### Styling & UI
- Tailwind CSS with custom color scheme for rule types:
  - DNAT rules: Blue (`bg-rule-dnat`)
  - Network rules: Green (`bg-rule-network`) 
  - Application rules: Orange (`bg-rule-application`)
- Responsive design with sidebar panels for rule details
- Interactive elements with hover states and click handlers

## Working with Azure Firewall Policies

### Expected Input Format
- Azure ARM template JSON export from Azure Portal
- Must contain `Microsoft.Network/firewallPolicies` resource type
- Supports complex nested structures with rule collection groups

### Rule Processing Metadata
Each processed rule includes:
- `processingOrder`: Global sequence number (1, 2, 3...)
- `ruleCategory`: 'DNAT' | 'Network' | 'Application'
- `groupPriority` & `collectionPriority`: Original Azure priorities
- `collectionName` & `collectionGroupName`: Hierarchy context

### Analysis Capabilities
- **Duplicate Detection**: Rules with identical source, destination, ports, protocols
- **Conflict Detection**: Allow/Deny conflicts, rule shadowing, overlapping permissions
- **Optimization Suggestions**: Rule combination opportunities, unused IP groups

## Development Tips

### Adding New Features
- Always update TypeScript interfaces in `firewall.types.ts` first
- Follow the existing processing pipeline: parse → process → analyze → render
- Use existing utility classes (`RuleProcessor`, `RuleAnalyzer`) for rule logic
- Maintain separation between Azure rule logic and UI presentation logic

### Testing with Real Data
- Export policies from Azure Portal: Firewall Policy → Export template → Download
- Use `template.json` file (not `parameters.json`)
- Test with policies containing multiple rule collection groups and rule types
- Verify processing order matches Azure Portal's rule precedence display

### Debugging
- Processing results logged to browser console with detailed rule analysis
- Use browser React DevTools to inspect component state
- Rule processing order can be verified against Azure Portal's numbering

## Automated Docker Management

### Docker Rebuild Subagent
The project includes a specialized subagent for automatic Docker container management located at `.claude/agents/docker-rebuild.md`. 

**When to Trigger Docker Rebuild:**
After making any of the following changes, use the Task tool to launch the `general-purpose` subagent with a prompt to "rebuild Docker containers to reflect latest code changes":
- Source code changes (TypeScript/React files in `src/`)
- Dependency changes (package.json modifications)
- Build configuration changes (vite.config.ts, tsconfig.json)
- Docker configuration changes (Dockerfile, docker-compose.yml)
- Any changes that affect the built application

**Auto-rebuild Process:**
1. Stop existing containers gracefully
2. Rebuild Docker images with latest changes
3. Restart containers with updated images
4. Verify successful deployment
5. Report status and handle any errors

This ensures the containerized version always reflects the latest codebase state without manual Docker commands.