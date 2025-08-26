# Azure Firewall Analyzer

# !! WIP - USE AT OWN RISK !!


A powerful web-based tool for visualizing, analyzing, and optimizing Azure Firewall policies. Upload your Azure Firewall Policy exports to understand rule processing order, identify duplicates and conflicts, and optimize your firewall configuration.

![Azure Firewall Analyzer](https://img.shields.io/badge/Azure-Firewall%20Analyzer-blue?style=flat-square&logo=microsoft-azure)
![React](https://img.shields.io/badge/React-19.1-blue?style=flat-square&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?style=flat-square&logo=typescript)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)

## 🎯 What This Tool Does

Azure Firewall policies can become complex with hundreds of rules across multiple collection groups. This tool helps you:

- **Visualize Rule Processing Order**: See exactly how Azure Firewall will process your rules, following the priority-based hierarchy
- **Identify Duplicate Rules**: Find rules that have identical configurations and can be consolidated
- **Detect Rule Conflicts**: Discover Allow/Deny conflicts and rules that shadow each other
- **Interactive Navigation**: Browse through rule hierarchies with table and mindmap visualizations
- **Export Analysis**: Generate reports of your policy analysis and optimization suggestions

## 🔒 Privacy & Security

**🛡️ Everything runs locally in your browser** - Your Azure Firewall policies never leave your machine:
- No data is sent to external servers
- No cloud processing or storage
- No user accounts or authentication required
- Your sensitive firewall configurations remain private and secure

## 🚀 Quick Start

### Option 1: Local Development (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/your-username/azure-firewall-analyzer.git
cd azure-firewall-analyzer

# Install dependencies
npm install

# Start development server
npm run dev
```

Open http://localhost:5173 in your browser.

### Option 2: Docker (Recommended for Production Use)

#### Production Build
```bash
# Build and run with docker-compose
docker-compose up --build
```

The application will be available at http://localhost:3000

#### Development with Hot Reload
```bash
# Run development server in Docker
docker-compose --profile dev up azure-firewall-analyzer-dev
```

Access at http://localhost:5173 with automatic code reloading.

### Option 3: Manual Docker Build
```bash
docker build -t azure-firewall-analyzer .
docker run -p 3000:80 azure-firewall-analyzer
```

## 📋 How to Use

### 1. Export Your Azure Firewall Policy

In Azure Portal:
1. Navigate to your Firewall Policy
2. Click **"Export template"** in the left menu
3. Click **"Download"** to get the ARM template
4. You'll need the `template.json` file (not `parameters.json`)

### 2. Upload and Analyze

1. Open Azure Firewall Analyzer in your browser
2. Drag and drop your `template.json` file or click to browse
3. The tool will automatically:
   - Parse your firewall policy
   - Apply Azure's rule processing logic
   - Analyze for duplicates and conflicts
   - Generate interactive visualizations

### 3. Explore Your Policy

- **Table View**: Hierarchical view of all rules with search and filtering
- **Mind Map**: Interactive node-based visualization of rule relationships
- **Issues View**: Dedicated view for duplicates, conflicts, and optimization suggestions
- **Rule Details**: Click any rule to see detailed configuration and metadata

## ✨ Key Features

### Rule Processing Logic
- Implements Azure Firewall's exact rule processing order
- Handles Rule Collection Group priorities (100-65000)
- Respects DNAT → Network → Application rule sequence
- Supports parent/child policy inheritance

### Smart Analysis
- **Duplicate Detection**: Identifies rules with identical source, destination, ports, and protocols
- **Conflict Analysis**: Finds Allow/Deny conflicts and rule shadowing
- **Optimization Suggestions**: Recommends rule consolidation opportunities
- **Processing Order Visualization**: Shows the exact sequence Azure Firewall follows

### Interactive Visualizations
- **Hierarchical Table**: Expandable tree view with search and filtering
- **Interactive Mind Map**: Zoomable, pannable node graph using ReactFlow
- **Real-time Updates**: Dynamic filtering and selection across all views
- **Responsive Design**: Works on desktop and tablet devices

## 🤝 Contributing

Contributions are welcome! This project is designed to help Azure administrators better understand and optimize their firewall configurations.

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Run linting: `npm run lint`
5. Build and test: `npm run build`
6. Submit a pull request

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🆘 Support

- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/endgor/azure-firewall-analyzer/issues)

## ⚠️ Disclaimer

This tool is for analysis and visualization purposes only. Always validate any configuration changes in a test environment before applying to production Azure Firewall policies. The tool processes policies locally and does not modify your actual Azure resources.