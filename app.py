import streamlit as st
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from api_integration import get_api_instance
from style import apply_custom_style, custom_header, custom_card, custom_stat_card
import re
import datetime
import json
from dns_sinkhole import DNSSinkhole
from url_analyzer import URLAnalyzer
from threat_intelligence import ThreatIntelligence
import threading
import time
import uuid
import socket
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import timedelta
from urllib.parse import urlparse


# DNS SINKHOLE HELPERS

def _clean_domain(domain):
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.strip(' /')

def _is_in_hosts(domain, hosts_path="/etc/hosts"):
    domain = _clean_domain(domain)
    try:
        with open(hosts_path, 'r') as f:
            hosts_content = f.read()
        return (f'127.0.0.1 {domain}' in hosts_content or
                f'127.0.0.1 www.{domain}' in hosts_content)
    except Exception:
        return False

def _resolve_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

def add_domain_and_www_to_sinkhole(domain, user_id, reason="Manual/Automatic Sinkhole Addition"):
    domain_clean = _clean_domain(domain)
    ok1 = sinkhole.add_domain_to_sinkhole(domain_clean, user_id, reason)
    ok2 = sinkhole.add_domain_to_sinkhole("www."+domain_clean, user_id, reason)
    return ok1 or ok2


# Database connection
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Dhruv001@",
        database="cybersecurity_db"
    )

# User authentication (login)
def authenticate_user(email, password):
    conn = connect_db()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user[2], password):
        return user
    return None

# User registration (sign-up)
def register_user(email, password, role):
    conn = connect_db()
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    query = "INSERT INTO users (email, password, role) VALUES (%s, %s, %s)"
    try:
        cursor.execute(query, (email, hashed_password, role))
        conn.commit()
        st.success("Registration successful! You can now log in.")
    except mysql.connector.IntegrityError:
        st.error("Email already exists. Please try a different one.")
    finally:
        conn.close()

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# GET USER EMAIL BY USER_ID
def get_user_email(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    query = "SELECT email FROM users WHERE user_id = %s"
    try:
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        return result[0] if result else None
    except mysql.connector.Error as err:
        print(f"Error getting user email: {err}")
        return None
    finally:
        conn.close()

# INIT COMPONENTS
sinkhole = DNSSinkhole()
url_analyzer = URLAnalyzer()
threat_intel = ThreatIntelligence()

# Save threat analysis results to database
def save_threat_analysis(user_id, website_link, malicious, suspicious, harmless, severity):
    # Add URL validation
    if not website_link.startswith(('http://', 'https://')):
        website_link = 'http://' + website_link
        
    conn = connect_db()
    cursor = conn.cursor()
    query = """
        INSERT INTO threat_indicator 
        (user_id, website_url, malicious_detections, suspicious_detections, 
         harmless_detections, severity_level, scan_date) 
        VALUES (%s, %s, %s, %s, %s, %s, NOW())
    """
    try:
        cursor.execute(query, (user_id, website_link, malicious, suspicious, 
                             harmless, severity))
        conn.commit()
        st.success("Scan results saved successfully!")
    except mysql.connector.Error as err:
        st.error(f"Error saving scan results: {err}")
    finally:
        conn.close()

def save_incident_report(user_id, website_link, severity, malicious_detections, resolution_status="Unresolved"):
    conn = connect_db()
    cursor = conn.cursor()
    query = """
        INSERT INTO incident_reports 
        (user_id, malicious_url, severity_level, malicious_detections, 
         report_date, resolution_status) 
        VALUES (%s, %s, %s, %s, NOW(), %s)
    """
    try:
        cursor.execute(query, (user_id, website_link, severity, malicious_detections, 
                             resolution_status))
        conn.commit()
        st.warning("⚠️ Due to malicious content detected, this URL has been added to incident reports.")
    except mysql.connector.Error as err:
        st.error(f"Error saving incident report: {err}")
    finally:
        conn.close()

def show_reports_page():
    st.header("Threat Analysis Reports")
    
    # Create tabs for different report types
    tab1, tab2 = st.tabs(["Incident Reports", "Manual Submissions"])
    
    with tab1:
        st.subheader("Incident Reports")
        
        # Filtering options
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "High (7-10)", "Medium (4-6)", "Low (1-3)"]
            )
        with col2:
            date_filter = st.selectbox(
                "Filter by Date",
                ["All Time", "Last 7 Days", "Last 30 Days", "Last 3 Months"]
            )
        
        # Get filtered incident reports
        reports = get_filtered_incident_reports(severity_filter, date_filter)
        
        if reports:
            for report in reports:
                with st.expander(f"URL: {report['malicious_url']} (Severity: {report['severity_level']})"):
                    st.write(f"Reported by: {report['email']}")
                    st.write(f"Malicious Detections: {report['malicious_detections']}")
                    st.write(f"Status: {report['resolution_status']}")
                    st.write(f"Date: {report['report_date']}")
    
    with tab2:
        st.subheader("Manual Threat Submissions")
        
        # Form for manual submission
        with st.expander("Submit New Threat Analysis"):
            url = st.text_input("URL")
            severity = st.slider("Severity Level", 1, 10, 5)
            description = st.text_area("Description")
            analysis = st.text_area("Analysis Results")
            
            if st.button("Submit Analysis"):
                save_manual_submission(
                    st.session_state.user_id,
                    url,
                    severity,
                    description,
                    analysis
                )
                st.success("Analysis submitted successfully!")
        
        # Display manual submissions
        st.subheader("Previous Submissions")
        submissions = get_manual_submissions()
        
        if submissions:
            for sub in submissions:
                with st.expander(f"URL: {sub['url']} (Severity: {sub['severity_level']})"):
                    st.write(f"Submitted by: {sub['email']}")
                    st.write(f"Description: {sub['description']}")
                    st.write(f"Analysis: {sub['analysis_result']}")
                    st.write(f"Date: {sub['submitted_at']}")

def get_filtered_incident_reports(severity_filter, date_filter):
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT ir.*, u.email 
        FROM incident_reports ir
        JOIN users u ON ir.user_id = u.user_id
        WHERE 1=1
    """
    
    params = []
    
    # Add severity filter
    if severity_filter != "All":
        if severity_filter == "High (7-10)":
            query += " AND severity_level >= 7"
        elif severity_filter == "Medium (4-6)":
            query += " AND severity_level BETWEEN 4 AND 6"
        elif severity_filter == "Low (1-3)":
            query += " AND severity_level < 4"
    
    # Add date filter
    if date_filter != "All Time":
        if date_filter == "Last 7 Days":
            query += " AND report_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        elif date_filter == "Last 30 Days":
            query += " AND report_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
        elif date_filter == "Last 3 Months":
            query += " AND report_date >= DATE_SUB(NOW(), INTERVAL 3 MONTH)"
    
    query += " ORDER BY report_date DESC"
    
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    except mysql.connector.Error as err:
        st.error(f"Error fetching reports: {err}")
        return []
    finally:
        conn.close()

def save_manual_submission(user_id, url, severity, description, analysis):
    conn = connect_db()
    cursor = conn.cursor()
    
    query = """
        INSERT INTO threat_analysis_submissions 
        (submitted_by, url, severity_level, description, analysis_result)
        VALUES (%s, %s, %s, %s, %s)
    """
    
    try:
        cursor.execute(query, (user_id, url, severity, description, analysis))
        conn.commit()
    except mysql.connector.Error as err:
        st.error(f"Error saving submission: {err}")
    finally:
        conn.close()

def get_manual_submissions():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT tas.*, u.email 
        FROM threat_analysis_submissions tas
        JOIN users u ON tas.submitted_by = u.user_id
        ORDER BY submitted_at DESC
    """
    
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except mysql.connector.Error as err:
        st.error(f"Error fetching submissions: {err}")
        return []
    finally:
        conn.close()

# Add this function for email validation
def is_valid_email(email):
    """Validate email format using regex pattern"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Add this function at the top with other helper functions
def get_mitigation_strategy(severity):
    strategies = {
        1: "No action needed; maintain regular security updates.",
        2: "Monitor network logs and ensure firewall is enabled.",
        3: "Use strong passwords and enable 2FA for all accounts.",
        4: "Perform regular vulnerability assessments.",
        5: "Educate users about phishing and implement email filtering.",
        6: "Install and update endpoint protection software.",
        7: "Restrict access to critical systems and apply least privilege.",
        8: "Enable IDS/IPS and conduct continuous threat monitoring.",
        9: "Isolate infected systems, apply patches immediately.",
        10: "Immediate incident response, full forensic analysis, and containment."
    }
    return strategies.get(round(severity), "Maintain standard security practices.")

# Initialize the new components
sinkhole = DNSSinkhole()
url_analyzer = URLAnalyzer()
threat_intel = ThreatIntelligence()

# Add a service manager to track running services
class ServiceManager:
    _instance = None
    _instance_id = None
    
    def __new__(cls):
        # Singleton pattern to ensure only one ServiceManager exists
        if cls._instance is None:
            cls._instance = super(ServiceManager, cls).__new__(cls)
            cls._instance_id = str(uuid.uuid4())
            print(f"Created new ServiceManager instance: {cls._instance_id}")
        return cls._instance
        
    def __init__(self):
        # Only initialize once
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self.service_status = {
                'honeynet': False, 
                'banner_rotation': False,
                'threat_intel': False
            }
            self.start_time = datetime.datetime.now()
            print(f"ServiceManager initialized at {self.start_time}")
    
    def start_services(self):
        """Start all security services if not already running"""
        # Use Streamlit session state for persistence across reruns
        if 'service_instance_id' in st.session_state and st.session_state.service_instance_id == self._instance_id:
            print(f"Services already started by this instance: {self._instance_id}")
            return
        
        if 'services_running' in st.session_state:
            print(f"Services already running from another instance. Current: {self._instance_id}")
            return
            
        print(f"Starting security services from instance {self._instance_id}...")
        
        # Set instance ID in session state
        st.session_state.service_instance_id = self._instance_id
        st.session_state.services_running = True
        
        # Start honeynet decoy services on higher ports
        for port in [2222, 2121, 2323, 8080, 8081, 8389]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                
                if result == 0:
                    print(f"Port {port} is already in use, skipping")
                    continue
                    
                if honeynet.start_decoy_service(port):
                    self.service_status['honeynet'] = True
            except Exception as e:
                if "Address already in use" in str(e):
                    print(f"Port {port} is already in use, likely from another session")
                else:
                    print(f"Could not start decoy service on port {port}: {e}")
        
        # Start banner rotation timer with safeguards
        try:
            if not hasattr(st.session_state, 'banner_thread_started'):
                def rotate_banners():
                    while True:
                        try:
                            honeynet.rotate_service_banners()
                        except Exception as e:
                            print(f"Error rotating banners: {e}")
                        time.sleep(3600)  # Rotate hourly
                        
                banner_thread = threading.Thread(target=rotate_banners, daemon=True)
                banner_thread.start()
                st.session_state.banner_thread_started = True
                self.service_status['banner_rotation'] = True
        except Exception as e:
            print(f"Error starting banner rotation: {e}")
        
        # Start threat intelligence updates
        try:
            threat_intel.start_background_updates(3600)  # Update hourly
            self.service_status['threat_intel'] = True
        except Exception as e:
            print(f"Error starting threat intelligence updates: {e}")
        
        print(f"Security services startup complete from instance {self._instance_id}")

# Initialize service manager
service_manager = ServiceManager()

# Start background services
def start_security_services():
    """Initialize all security services"""
    global sinkhole, honeynet, threat_intel
    
    if ServiceManager.is_initialized():
        return ServiceManager.get_services()
    
    try:
        # Initialize services
        sinkhole = DNSSinkhole()
        threat_intel = ThreatIntelligence()
        
        # Start DNS sinkhole server
        sinkhole.start_dns_server()
        
        # Start threat intelligence updates
        threat_intel.start_background_updates(interval=3600)
        
        ServiceManager.mark_initialized(sinkhole, honeynet, threat_intel)
        return sinkhole, honeynet, threat_intel
        
    except Exception as e:
        st.error(f"Error starting security services: {e}")
        return None, None, None

# Enhance the URL analysis in the main function
def enhanced_url_scan(website_link, user_id):
    """Enhanced URL scanning with automatic sinkhole integration"""
    user_email = get_user_email(user_id)
    
    # Step 1: De-obfuscate URL
    analysis_results = url_analyzer.analyze_url(website_link)
    resolved_url = analysis_results["resolved_url"]
    
    # Step 2: Check threat intelligence
    intel_match = threat_intel.check_indicator(resolved_url)
    if intel_match:
        scan_results = {
            'malicious': 15,
            'suspicious': 5,
            'harmless': 0,
            'severity': 10,
            'threat_details': f"Matched known threat: {intel_match['threat_type']} from {intel_match['source']}"
        }
        
        # Automatically add to sinkhole with threat intel details
        auto_added = sinkhole.auto_add_malicious_domain(
            resolved_url, 
            user_id, 
            scan_results, 
            scan_results['severity']
        )
        
        if auto_added:
            st.success(f"🤖 AUTOMATIC PROTECTION: {resolved_url} has been added to DNS sinkhole!")
            st.info(f"🛡️ All future requests to this domain will be automatically blocked")
                                      
        return scan_results, analysis_results
    
    # Step 3: Use API for normal scanning
    api = get_api_instance()
    scan_results = api.scan_url(resolved_url, user_id)
    
    # Step 4: AUTOMATIC SINKHOLE ADDITION based on API results
    if scan_results:
        should_auto_sinkhole = False
        sinkhole_reason = ""
        
        # Define criteria for automatic sinkhole addition
        if scan_results['malicious'] >= 5:  # High malicious score
            should_auto_sinkhole = True
            sinkhole_reason = f"High malicious score: {scan_results['malicious']}"
        elif scan_results['severity'] >= 8:  # Very high severity
            should_auto_sinkhole = True
            sinkhole_reason = f"Critical severity level: {scan_results['severity']}/10"
        elif scan_results['malicious'] >= 3 and scan_results['severity'] >= 6:  # Moderate but concerning
            should_auto_sinkhole = True
            sinkhole_reason = f"Moderate threat (Malicious: {scan_results['malicious']}, Severity: {scan_results['severity']})"
        
        # Automatically add to sinkhole if criteria met
        if should_auto_sinkhole:
            auto_added = sinkhole.auto_add_malicious_domain(
                resolved_url, 
                user_id, 
                scan_results, 
                scan_results['severity']
            )
            
            if auto_added:
                st.success(f"🤖 AUTOMATIC PROTECTION ACTIVATED!")
                st.info(f"🛡️ {resolved_url} has been automatically added to DNS sinkhole")
                st.info(f"📋 Reason: {sinkhole_reason}")
                st.warning(f"⚠️ All future access attempts to this domain will be blocked")
            else:
                st.warning(f"⚠️ Failed to automatically protect against {resolved_url}")
    
    return scan_results, analysis_results

# Add a helper function to get user email from user ID
def get_user_email(user_id):
    """Get user email by user ID"""
    conn = connect_db()
    cursor = conn.cursor()
    query = "SELECT email FROM users WHERE user_id = %s"
    try:
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        return result[0] if result else None
    except mysql.connector.Error as err:
        print(f"Error getting user email: {err}")
        return None
    finally:
        conn.close()

# Streamlit app
def main():
    # Apply custom styling
    apply_custom_style()
    
    # Start security services if not already running
    if 'services_running' not in st.session_state:
        try:
            service_manager.start_services()
        except Exception as e:
            print(f"Error initializing security services: {e}")
            st.session_state.services_running = False  # Mark as failed so we can retry
    
    # Custom title with cyberpunk style
    st.markdown("""
        <h1 class="stTitle">Cybersecurity Intelligent<br>Threat Detection</h1>
    """, unsafe_allow_html=True)

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        # Sign-In or Sign-Up Options
        option = st.selectbox("Choose an option", ["Login", "Sign Up"])

        if option == "Login":
            st.header("Login")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            
            if st.button("Login"):
                if not email:
                    st.error("Please enter your email.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                elif not password:
                    st.error("Please enter your password.")
                else:
                    user = authenticate_user(email, password)
                    if user:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user[0]
                        st.session_state.role = user[3]
                        st.success("Logged in successfully!")
                        st.rerun()
                    else:
                        st.error("Invalid email or password.")

        elif option == "Sign Up":
            st.header("Sign Up")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            role = st.selectbox("Role", ["Admin", "Reviewer"])
            
            if st.button("Sign Up"):
                if not email:
                    st.error("Please enter your email.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                elif not password:
                    st.error("Please enter a password.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters long.")
                else:
                    register_user(email, password, role)
        return

    # Custom navigation header with logout button
    st.sidebar.markdown("""
        <div class="nav-header">
            <h3>NAVIGATION CONSOLE</h3>
        </div>
    """, unsafe_allow_html=True)
    
    # Add logout button to sidebar
    if st.sidebar.button("🔒 Logout", key="logout_button"):
        st.session_state.clear()  # Clear all session state
        st.rerun()  # Use st.rerun() instead of experimental_rerun()
    
    # Add a divider in sidebar
    st.sidebar.markdown("<hr style='border: 1px solid #0fe0b0; margin: 20px 0;'>", unsafe_allow_html=True)
    
    # Custom navigation options
    nav_options = ["Threat Detection", "Reports", "Security Dashboard"]
    page = st.sidebar.selectbox("Navigation", nav_options, format_func=lambda x: f">> {x}", label_visibility="collapsed")
    
    if page == "Threat Detection":
        custom_header("Threat Analysis Console")
        # Main app after login
        st.header("Threat Detection")
        website_link = st.text_input("Enter website link to analyze:")
        if st.button("Detect Threat"):
            if website_link:
                with st.spinner('Analyzing website...'):
                    if not website_link.startswith(('http://', 'https://')):
                        website_link = 'http://' + website_link

                    scan_results, url_analysis = enhanced_url_scan(website_link, st.session_state.user_id)
                    
                    if scan_results:
                        # Display scan results
                        st.write("Scan Results:")
                        st.write(f"- Malicious Score: {scan_results['malicious']}")
                        st.write(f"- Suspicious Score: {scan_results['suspicious']}")
                        st.write(f"- Harmless Score: {scan_results['harmless']}")
                        
                        if scan_results.get('patterns_detected'):
                            st.warning("Suspicious Patterns Detected:")
                            for pattern in scan_results['patterns_detected']:
                                st.write(f"- Pattern: {pattern['pattern']} (Type: {pattern['type']})")
                        
                        if scan_results.get('local_database_match'):
                            st.error("⚠️ URL matches known malicious patterns in local database!")
                        
                        # Save results to threat_indicator table (only once)
                        save_threat_analysis(
                            st.session_state.user_id,
                            website_link,
                            scan_results['malicious'],
                            scan_results['suspicious'],
                            scan_results['harmless'],
                            scan_results['severity']
                        )
                        
                        # Check if URL should be reported (malicious or high severity)
                        should_report = (
                            scan_results['malicious'] > 0 or 
                            scan_results['severity'] >= 7 or 
                            (scan_results['suspicious'] > 0 and scan_results['severity'] >= 5)
                        )
                        
                        if should_report:
                            # Always use API results, no local malware repository check
                            if scan_results['malicious'] > 0:
                                st.error("🚨 Malicious URL Detected!")
                                resolution_status = "Unresolved - Malicious"
                                
                                # Display threat details from API
                                st.error(f"Severity Level: {scan_results['severity']}/10")
                                
                                # If we have specific threat info from the API
                                if scan_results.get('threat_details'):
                                    st.warning(f"Threat Details: {scan_results.get('threat_details')}")
                            else:
                                st.warning("⚠️ Suspicious URL Detected!")
                                resolution_status = "Unresolved - Suspicious"
    
                            # Save to incident report
                            save_incident_report(
                                st.session_state.user_id,
                                website_link,
                                scan_results['severity'],
                                scan_results['malicious'],
                                resolution_status
                            )
                            
                            # Additional user guidance
                            st.info("👉 Security team has been notified and will investigate this threat.")
                            if scan_results['severity'] >= 8:
                                st.error("⚠️ CRITICAL: Immediate action recommended. Avoid accessing this URL.")
                        
                        # Display severity level message
                        severity = round(scan_results['severity'])
                        if severity >= 7:
                            st.error(f"High threat level detected! Severity: {severity}/10")
                        elif severity >= 4:
                            st.warning(f"Medium threat level detected. Severity: {severity}/10")
                        else:
                            st.success(f"Low threat level. Severity: {severity}/10")

                        # Get mitigation strategy
                        mitigation = get_mitigation_strategy(severity)
                        
                        # Create styled container for recommendation
                        st.markdown("---")  # Add a separator
                        st.markdown("""
                            <h3 style='color: #0fe0b0; margin: 20px 0;'>🛡️ Recommended Action</h3>
                        """, unsafe_allow_html=True)
                        
                        # Display recommendation in a styled container
                        st.markdown(f"""
                            <div style='
                                background: rgba(0, 0, 0, 0.8);
                                border: 1px solid #0fe0b0;
                                border-radius: 5px;
                                padding: 20px;
                                margin: 10px 0;
                            '>
                                <div style='
                                    color: #0fe0b0;
                                    font-family: "Courier New", monospace;
                                    margin-bottom: 10px;
                                '>
                                    Severity Level: {severity}/10
                                </div>
                                <div style='
                                    color: #0fe0b0;
                                    font-family: "Courier New", monospace;
                                    padding: 10px;
                                    background: rgba(15, 224, 176, 0.05);
                                    border-left: 3px solid #0fe0b0;
                                '>
                                    {mitigation}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                        
                        if url_analysis['is_obfuscated']:
                            st.warning(f"⚠️ URL was obfuscated! Resolved to: {url_analysis['resolved_url']}")
                        
                        if any([url_analysis['has_js_redirects'], url_analysis['has_hidden_elements'], 
                                url_analysis['has_fake_forms'], url_analysis['has_suspicious_scripts']]):
                            st.error("🚨 Suspicious JavaScript behaviors detected!")
                            st.info(url_analysis['behavior_details'])
                    else:
                        st.error("Failed to analyze website. Please try again later.")
            else:
                st.warning("Please enter a website link.")
    elif page == "Reports":
        show_reports_page()
    elif page == "Security Dashboard":
        show_security_dashboard()

def show_auto_sinkhole_dashboard():
    """Show automatic sinkhole activity and statistics"""
    st.subheader("🤖 Automatic DNS Sinkhole Protection")
    
    # Get sinkhole statistics
    stats = sinkhole.get_sinkhole_statistics()
    
    # Display statistics in columns
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Protected Domains",
            stats.get('total_domains', 0),
            delta=f"{stats.get('recent_additions', 0)} in 24h"
        )
    
    with col2:
        st.metric(
            "Auto-Added Domains",
            stats.get('auto_added', 0)
        )
    
    with col3:
        st.metric(
            "Manually Added",
            stats.get('manual_added', 0)
        )
    
    with col4:
        st.metric(
            "Blocked Requests",
            stats.get('blocked_requests', 0)
        )
    
    # Show threat categories if available
    if stats.get('threat_categories'):
        st.subheader("Threat Categories")
        categories_df = pd.DataFrame(stats['threat_categories'])
        fig = px.pie(
            categories_df, 
            values='count', 
            names='category',
            title="Distribution of Sinkholed Domains by Threat Type"
        )
        fig.update_layout(
            template='plotly_dark',
            plot_bgcolor='rgba(0, 0, 0, 0)',
            paper_bgcolor='rgba(0, 0, 0, 0)',
            font=dict(color='#0fe0b0')
        )
        st.plotly_chart(fig)
    
    # Show recent auto-additions
    st.subheader("Recent Automatic Additions")
    auto_log = sinkhole.get_auto_sinkhole_log(20)
    
    if auto_log:
        # Create DataFrame for display
        df = pd.DataFrame(auto_log)
        
        # Display in a nice table
        for entry in auto_log[:10]:  # Show last 10
            with st.expander(f"🤖 {entry['domain']} (Severity: {entry['severity_level']}/10)"):
                st.write(f"**Original URL:** {entry['original_url']}")
                st.write(f"**Added by:** {entry.get('email', 'System')}")
                st.write(f"**Detection Scores:** Malicious: {entry['malicious_score']}, Suspicious: {entry['suspicious_score']}")
                st.write(f"**Added at:** {entry['added_at']}")
                st.write(f"**Source:** {entry['detection_source']}")
    else:
        st.info("No automatic additions yet.")
    
    # Manual sinkhole addition
    st.subheader("Manual Domain Addition")
    with st.expander("Add Domain Manually"):
        st.info("""
        🔒 **DNS Sinkhole Protection System**
        
        When you add a domain here:
        1. It will be blocked at the DNS level (hosts file)
        2. All HTTP traffic will be redirected to a blocking page
        3. HTTPS sites will show certificate warnings (this is normal)
        4. You may need to clear your browser cache or restart your browser
        
        **For testing, try adding:** `secure.eicar.org` or `test-malware.com`
        """)
        
        manual_domain = st.text_input(
            "Domain to add:",
            help="Enter domain without http:// or https:// (e.g., malicious-site.com)"
        )
        manual_reason = st.text_area("Reason:", value="Manual addition by administrator")
        
        if st.button("Add to Sinkhole", type="primary"):
            if manual_domain:
                with st.spinner("Adding domain to sinkhole... This may require admin password."):
                    success = sinkhole.add_domain_to_sinkhole(
                        manual_domain, 
                        st.session_state.user_id, 
                        manual_reason
                    )
                if success:
                    st.success(f"✅ {manual_domain} added to sinkhole successfully!")
                    
                    # Show testing instructions
                    st.info(f"""
                    🧪 **Testing the Sinkhole:**
                    
                    1. **Clear your browser cache** (Ctrl+Shift+Delete)
                    2. **Restart your browser** completely  
                    3. **Try accessing:** `http://{manual_domain}` (not https://)
                    4. **Alternative:** Open in Incognito/Private mode
                    5. **You should see:** A red blocking page with "DOMAIN BLOCKED"
                    
                    ⚠️ **Note:** HTTPS sites may show certificate warnings - this is expected behavior.
                    """)
                    
                    sinkhole._update_sinkhole_stats('manual_added')
                    st.rerun()
                else:
                    st.error(f"❌ Failed to add {manual_domain} to sinkhole")
                    st.warning("""
                    **Troubleshooting:**
                    - Check if you entered the admin password correctly
                    - Make sure you have administrator privileges
                    - Try running the application with sudo if needed
                    """)
            else:
                st.warning("Please enter a domain name")
    
    # Sinkhole Testing Section
    st.subheader("Sinkhole Testing & Verification")
    with st.expander("Test if DNS Sinkhole is Working"):
        st.write("**🧪 Test a sinkholed domain to verify blocking is active:**")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            test_domain = st.selectbox(
                "Select domain to test:",
                ["secure.eicar.org", "test-malware.com", "evil-site.net", "badsite.localhost"] + 
                ([d['domain'] for d in sinkhole.get_sinkholed_domains(10)] if sinkhole.get_sinkholed_domains(10) else [])
            )
        with col2:
            if st.button("Test Domain", type="secondary"):
                if test_domain:
                    # Check if domain is in hosts file
                    is_blocked = sinkhole._is_domain_sinkholed(test_domain)
                    dns_resolves = sinkhole._verify_sinkhole_active(test_domain)
                    
                    if is_blocked:
                        st.success(f"✅ {test_domain} is properly sinkholed!")
                        
                        # Show DNS resolution test
                        try:
                            import socket
                            resolved_ip = socket.gethostbyname(test_domain)
                            if resolved_ip == "127.0.0.1":
                                st.success(f"🎯 DNS Resolution: {test_domain} → {resolved_ip} ✅")
                            else:
                                st.warning(f"⚠️ DNS Resolution: {test_domain} → {resolved_ip} (Expected: 127.0.0.1)")
                        except Exception as e:
                            st.error(f"❌ DNS Resolution failed: {e}")
                        
                        st.info(f"""
                        **✅ Sinkhole Status: ACTIVE**
                        
                        **To verify blocking is working:**
                        1. Open browser and go to: `http://{test_domain}`
                        2. You should see a red "DOMAIN BLOCKED" page
                        3. If not working, try:
                           - Clear browser cache (Ctrl+Shift+Delete)
                           - Restart browser completely
                           - Try in Incognito/Private mode
                           - Wait 30-60 seconds for DNS propagation
                        """)
                    else:
                        st.error(f"❌ {test_domain} is NOT sinkholed")
                        st.info("Add this domain to the sinkhole first using the manual addition section above.")

# Update the Security Dashboard tab
def show_security_dashboard():
    st.header("Security Operations Dashboard")
    
    tab1, tab2, tab3 = st.tabs([
        "DNS Sinkhole", 
        "Auto-Protection", 
        "Threat Intel"
    ])
    
    with tab1:
        st.subheader("DNS Sinkhole - Currently Protected Domains")
        try:
            sinkholed = sinkhole.get_sinkholed_domains(100)
            if sinkholed:
                st.write(f"**Currently Protected: {len(sinkholed)} domains**")
                
                # Create header columns
                col1, col2, col3, col4, col5 = st.columns([3, 2, 3, 1, 1])
                with col1:
                    st.write("**Domain**")
                with col2:
                    st.write("**Type**")
                with col3:
                    st.write("**Blocked At**")
                with col4:
                    st.write("**Reason**")
                with col5:
                    st.write("**Action**")
                
                st.divider()
                
                # Display each domain with remove button
                for i, domain in enumerate(sinkholed):
                    col1, col2, col3, col4, col5 = st.columns([3, 2, 3, 1, 1])
                    
                    with col1:
                        st.write(f"🌐 **{domain['domain']}**")
                    
                    with col2:
                        prefix = "🤖 Auto" if "AUTO-DETECTED" in domain['reason'] else "👤 Manual"
                        st.write(prefix)
                    
                    with col3:
                        st.write(f"🕒 {domain['blocked_at']}")
                    
                    with col4:
                        reason_short = domain['reason'][:20] + "..." if len(domain['reason']) > 20 else domain['reason']
                        st.write(f"📝 {reason_short}")
                    
                    with col5:
                        if st.button("🗑️", key=f"remove_{i}_{domain['domain']}", help=f"Remove {domain['domain']} from sinkhole"):
                            # Confirm removal
                            if st.session_state.get(f'confirm_removal_{domain["domain"]}') != True:
                                st.session_state[f'confirm_removal_{domain["domain"]}'] = True
                                st.warning(f"⚠️ Click remove again to confirm removal of **{domain['domain']}**")
                            else:
                                # Perform removal
                                with st.spinner(f"Removing {domain['domain']} from sinkhole... This may require admin password."):
                                    success = sinkhole.remove_domain_from_sinkhole(
                                        domain['domain'], 
                                        st.session_state.user_id, 
                                        "Manual removal via dashboard"
                                    )
                                
                                if success:
                                    st.success(f"✅ Successfully removed {domain['domain']} from sinkhole!")
                                    st.info("""
                                    🔄 **Domain Removed Successfully!**
                                    
                                    The domain has been removed from:
                                    - ✅ Sinkhole database
                                    - ✅ Hosts file (all variants)
                                    - ✅ DNS cache flushed
                                    
                                    **To verify removal:**
                                    1. Clear your browser cache (Ctrl+Shift+Delete)
                                    2. Restart your browser completely
                                    3. Try accessing the domain - it should work normally now
                                    4. Or test in Incognito/Private mode
                                    """)
                                    # Clear confirmation state
                                    if f'confirm_removal_{domain["domain"]}' in st.session_state:
                                        del st.session_state[f'confirm_removal_{domain["domain"]}']
                                    st.rerun()
                                else:
                                    st.error(f"❌ Failed to remove {domain['domain']}. Please try again.")
                                    st.warning("""
                                    **Troubleshooting:**
                                    - Make sure you entered the admin password correctly
                                    - Check that you have administrator privileges
                                    - Try running the application with sudo if needed
                                    """)
                                    if f'confirm_removal_{domain["domain"]}' in st.session_state:
                                        del st.session_state[f'confirm_removal_{domain["domain"]}']
                    
                    if i < len(sinkholed) - 1:  # Don't add divider after last item
                        st.divider()
                
                # Manual removal section
                st.markdown("---")
                st.subheader("🗑️ Manual Domain Removal")
                
                col1, col2 = st.columns([3, 1])
                with col1:
                    domain_to_remove = st.text_input(
                        "Enter domain to remove from sinkhole", 
                        placeholder="example.com",
                        help="Enter the exact domain name (without http/https)"
                    )
                with col2:
                    st.write("")  # Spacing
                    if st.button("🗑️ Remove Domain", type="secondary"):
                        if domain_to_remove:
                            # Confirm removal
                            if st.session_state.get('confirm_manual_removal') != domain_to_remove:
                                st.session_state.confirm_manual_removal = domain_to_remove
                                st.warning(f"⚠️ Click again to confirm removal of: **{domain_to_remove}**")
                            else:
                                # Perform removal
                                with st.spinner(f"Removing {domain_to_remove} from sinkhole... This may require admin password."):
                                    success = sinkhole.remove_domain_from_sinkhole(
                                        domain_to_remove, 
                                        st.session_state.user_id, 
                                        "Manual removal via dashboard"
                                    )
                                
                                if success:
                                    st.success(f"✅ {domain_to_remove} removed from sinkhole!")
                                    st.info("""
                                    🔄 **Domain Removed Successfully!**
                                    
                                    **To verify the domain is now accessible:**
                                    1. Clear your browser cache (Ctrl+Shift+Delete)
                                    2. Restart your browser completely
                                    3. Try accessing the domain - it should work normally now
                                    4. DNS changes may take 30-60 seconds to propagate
                                    """)
                                    del st.session_state.confirm_manual_removal
                                    st.rerun()
                                else:
                                    st.error(f"❌ Failed to remove {domain_to_remove}. Domain may not be in sinkhole.")
                                    del st.session_state.confirm_manual_removal
                        else:
                            st.error("Please enter a domain name")
            else:
                st.info("No domains have been sinkholed yet.")
        except Exception as e:
            st.error(f"Error retrieving sinkholed domains: {str(e)}")
    
    with tab2:
        show_auto_sinkhole_dashboard()
    
    with tab3:
        st.subheader("Threat Intelligence")
        st.text("Connected to 3 threat feeds:")
        st.text("- PhishTank (Phishing URLs)")
        st.text("- URLhaus (Malware URLs)")
        st.text("- OpenPhish (Phishing URLs)")
        
        # Add manual IOC search with better display
        indicator = st.text_input("Search for Indicator of Compromise:")
        if st.button("Search Threat Intel") and indicator:
            try:
                with st.spinner("Scanning threat intelligence sources..."):
                    result = threat_intel.check_indicator(indicator)
                    if result:
                        st.error(f"⚠️ Match found! {result['indicator_value']} is a known {result['threat_type']} indicator")
                        
                        # Display metadata if available
                        if result.get('metadata'):
                            try:
                                metadata = json.loads(result['metadata'])
                                
                                # Create columns for stats
                                if 'malicious' in metadata:
                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.metric("Malicious", metadata.get('malicious', 0))
                                    with col2:
                                        st.metric("Suspicious", metadata.get('suspicious', 0))
                                    with col3:
                                        st.metric("Harmless", metadata.get('harmless', 0))
                            
                                # Show vendor reports
                                if 'vendors' in metadata and metadata['vendors']:
                                    st.subheader("Detection Reports")
                                    for vendor in metadata['vendors']:
                                        st.text(f"• {vendor}")
                                        
                                # Show additional metadata
                                if 'vt_vendors' in metadata and metadata['vt_vendors']:
                                    st.subheader("Security Vendors")
                                    for vendor in metadata['vt_vendors']:
                                        st.text(f"• {vendor}")
                            except:
                                st.info(f"Source: {result['source']}, Confidence: {round(result['confidence']*100)}%")
                        else:
                            st.info(f"Source: {result['source']}, Confidence: {round(result['confidence']*100)}%")
                        
                        # Add sinkhole option
                        if st.button("Add to DNS Sinkhole"):
                            if 'user_id' in st.session_state:
                                domain = result['indicator_value']
                                sinkhole.add_domain_to_sinkhole(domain, st.session_state.user_id, f"Added from threat intelligence: {result['threat_type']}")
                                st.success(f"Domain {domain} added to sinkhole")
                            else:
                                st.warning("You must be logged in to add domains to the sinkhole")
                    else:
                        st.success("No threat intelligence match found for this indicator.")
            except Exception as e:
                st.error(f"Error searching threat intelligence: {str(e)}")

if __name__ == "__main__":
    main()
