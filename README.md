# 🛡️ Cybersecurity Threat Intelligence System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive real-time cybersecurity threat intelligence platform designed for network security monitoring, threat analysis, and automated defense mechanisms. Built with Streamlit and integrated with multiple threat intelligence APIs.

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Technologies](#-technologies-used)
- [Installation](#-installation)
- [Configuration](#️-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [API Integration](#-api-integration)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 Threat Intelligence
- **Real-time Threat Analysis**: Continuous monitoring and analysis of cybersecurity threats
- **Malware Database**: Comprehensive database of known malware signatures and behaviors
- **Threat Visualization**: Interactive network graphs showing threat relationships and patterns
- **Severity Classification**: Automated threat severity scoring and categorization

### 🚫 DNS Sinkhole
- **Malicious Domain Blocking**: Automatically block access to known malicious domains
- **Custom Blocklists**: Maintain and update custom domain blocklists
- **Real-time DNS Resolution**: Monitor and log DNS queries for suspicious activity
- **Automatic Host File Management**: Seamless integration with system host files

### 🔗 URL Analysis
- **URL Risk Assessment**: Analyze URLs for potential security threats
- **Phishing Detection**: Identify phishing attempts and suspicious links
- **Domain Reputation Checking**: Check domain reputation against threat intelligence feeds
- **Pattern Matching**: Advanced regex-based pattern detection for malicious URLs

### 📊 Data Visualization
- **Interactive Dashboards**: Real-time security metrics and KPIs
- **Network Graphs**: Visualize threat networks and relationships
- **Statistical Analysis**: Comprehensive threat statistics and trends
- **Export Capabilities**: Export data in multiple formats (CSV, JSON)

### 🔐 Security Features
- **User Authentication**: Secure user login and session management
- **Role-Based Access Control**: Different permission levels for users
- **Audit Logging**: Complete audit trail of all security events
- **Encrypted Credentials**: Secure storage of sensitive information

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Streamlit Frontend                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Threat     │  │     DNS      │  │     URL      │ │
│  │ Intelligence │  │   Sinkhole   │  │   Analyzer   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                          │
├─────────────────────────────────────────────────────────┤
│                   API Integration Layer                  │
│         (External Threat Intelligence APIs)              │
├─────────────────────────────────────────────────────────┤
│                    Data Layer                            │
│              (MySQL/PostgreSQL Database)                 │
└─────────────────────────────────────────────────────────┘
```

## 🛠 Technologies Used

### Backend
- **Python 3.8+**: Core programming language
- **Streamlit**: Web application framework
- **MySQL Connector**: Database connectivity
- **Werkzeug**: Security utilities for password hashing

### Data Processing & Visualization
- **Pandas**: Data manipulation and analysis
- **NetworkX**: Network graph creation and analysis
- **PyVis**: Interactive network visualizations
- **Plotly**: Interactive charts and graphs

### APIs & Integration
- **REST APIs**: Integration with threat intelligence feeds
- **DNS Resolution**: Custom DNS lookup and sinkhole capabilities
- **Web Scraping**: Data collection from threat sources

### Database
- **MySQL/PostgreSQL**: Primary data storage
- **SQL**: Database queries and management

## 📥 Installation

### Prerequisites

- Python 3.8 or higher
- MySQL Server 8.0+ or PostgreSQL 12+
- Git
- pip (Python package manager)

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/Cybersecurity-Threat-Intelligence-System.git
cd Cybersecurity-Threat-Intelligence-System
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Database Setup

1. Create a new MySQL/PostgreSQL database:

```sql
CREATE DATABASE cybersecurity_db;
```

2. Import the database schema:

```bash
# For MySQL
mysql -u your_username -p cybersecurity_db < new.sql

# For PostgreSQL
psql -U your_username -d cybersecurity_db -f new.sql
```

### Step 5: Configure Environment Variables

Create a `.env` file in the root directory:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=cybersecurity_db
DB_USER=your_username
DB_PASSWORD=your_password

# API Keys (Optional - for enhanced features)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ALIENVAULT_API_KEY=your_alienvault_api_key

# Application Settings
SECRET_KEY=your_secret_key_here
DEBUG=False
```

## ⚙️ Configuration

### DNS Sinkhole Configuration

Edit `sinkholed_domains.conf` to add custom domains:

```conf
# Add malicious domains (one per line)
malicious-site.com
phishing-domain.net
suspicious-website.org
```

### API Integration

Configure API endpoints in `api_integration.py`:

```python
API_CONFIG = {
    'virustotal': {
        'api_key': os.getenv('VIRUSTOTAL_API_KEY'),
        'endpoint': 'https://www.virustotal.com/api/v3/'
    }
}
```

## 🚀 Usage

### Starting the Application

```bash
streamlit run app.py
```

The application will start on `http://localhost:8501`

### Basic Operations

#### 1. User Authentication
- Navigate to the login page
- Enter your credentials or register a new account
- Access the dashboard upon successful authentication

#### 2. Threat Analysis
- Go to "Threat Intelligence" section
- View real-time threat data and statistics
- Explore interactive threat network visualizations

#### 3. DNS Sinkhole Management
- Access "DNS Sinkhole" from the menu
- Add domains to blocklist
- View blocked domains and statistics
- Test domain resolution

#### 4. URL Analysis
- Navigate to "URL Analyzer"
- Enter a URL to analyze
- Review threat assessment results
- View detailed security metrics

## 📁 Project Structure

```
Cybersecurity-Threat-Intelligence-System/
│
├── app.py                              # Main Streamlit application
├── api_integration.py                  # External API integration
├── dns_sinkhole.py                     # DNS sinkhole functionality
├── threat_intelligence.py              # Threat intelligence module
├── url_analyzer.py                     # URL analysis engine
├── data_import.py                      # Data import utilities
├── style.py                            # UI styling and themes
│
├── new.sql                             # Database schema
├── query.sql                           # SQL queries
├── requirements.txt                    # Python dependencies
├── .gitignore                          # Git ignore rules
├── README.md                           # Project documentation
│
├── lib/                                # Frontend libraries
│   ├── vis-9.1.2/                     # Network visualization
│   │   ├── vis-network.min.js
│   │   └── vis-network.css
│   └── tom-select/                     # Enhanced select inputs
│       ├── tom-select.complete.min.js
│       └── tom-select.css
│
├── cybersecurity_severity_levels.csv   # Severity classification data
├── processed_malware_data.csv          # Malware database
├── sinkholed_domains.conf              # Blocked domains list
└── threat_network.html                 # Network visualization output
```

## 🔌 API Integration

This system integrates with multiple threat intelligence APIs:

### Supported APIs
- **VirusTotal**: Malware scanning and URL analysis
- **AlienVault OTX**: Open Threat Exchange data
- **AbuseIPDB**: IP reputation checking
- **URLhaus**: Malware URL database

### Adding Custom APIs

Edit `api_integration.py`:

```python
def get_threat_data(indicator):
    """
    Fetch threat data from custom API
    """
    # Your implementation here
    pass
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Write unit tests for new features
- Update documentation as needed

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **RVCE Students** - *Initial work* - RVCE Network & Security Lab

## 🙏 Acknowledgments

- RVCE College - Network and Security Lab
- Open-source threat intelligence communities
- Contributors and maintainers

## 🔮 Future Enhancements

- [ ] Machine Learning-based threat prediction
- [ ] Integration with SIEM systems
- [ ] Mobile application
- [ ] Automated incident response
- [ ] Multi-language support
- [ ] Advanced reporting features
- [ ] Cloud deployment options

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

**Made with ❤️ for Cybersecurity**
