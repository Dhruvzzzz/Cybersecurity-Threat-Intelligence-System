# Network & Cybersecurity Project

A comprehensive network security and threat intelligence system built with Flask and various cybersecurity tools.

## Features

- **Threat Intelligence**: Real-time threat analysis and monitoring
- **DNS Sinkhole**: Block malicious domains and prevent DNS-based attacks
- **URL Analyzer**: Analyze URLs for potential security threats
- **API Integration**: Integration with external threat intelligence APIs
- **Network Visualization**: Interactive network threat visualization using vis.js
- **Data Processing**: Process and analyze malware data

## Technologies Used

- Python 3
- Flask
- PostgreSQL/MySQL
- vis.js for network visualization
- Tom Select for enhanced select inputs

## Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd "NPS lab EL"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file with your configuration:
```
DATABASE_URL=your_database_url
API_KEY=your_api_key
```

4. Initialize the database:
```bash
psql -U your_username -d your_database -f new.sql
```

5. Run the application:
```bash
python app.py
```

## Project Structure

- `app.py` - Main Flask application
- `api_integration.py` - API integration logic
- `dns_sinkhole.py` - DNS sinkhole implementation
- `threat_intelligence.py` - Threat intelligence module
- `url_analyzer.py` - URL analysis functionality
- `data_import.py` - Data import utilities
- `lib/` - Frontend libraries (vis.js, tom-select)

## License

This project is for educational purposes (RVCE - NPS Lab).
