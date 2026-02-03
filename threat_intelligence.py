import mysql.connector
import requests
import time
import json
import threading
import datetime
import re
from urllib.parse import urlparse
import logging
import os
from dotenv import load_dotenv
import base64

# At the top of your file, load environment variables
load_dotenv()  # This loads API keys from a .env file

class ThreatIntelligence:
    def __init__(self, db_config=None):
        # Initialize as before
        self.db_config = db_config or {
            'host': 'localhost',
            'user': 'root',
            'password': 'Dhruv001@',
            'database': 'cybersecurity_db'
        }
        
        # Set up threading variables first to avoid race conditions
        self.running = False
        self.update_thread = None
        self.update_lock = threading.Lock()
        self.cache = {}
        
        # Create database tables
        try:
            self._ensure_threat_intel_tables()
        except Exception as e:
            print(f"Error initializing threat intel tables: {e}")
    
        # Load API keys from environment variables
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
            'alienvault': os.getenv('ALIENVAULT_API_KEY')
        }
        
        print(f"API keys loaded: VT: {'✓' if self.api_keys['virustotal'] else '✗'}, "
              f"AbuseIPDB: {'✓' if self.api_keys['abuseipdb'] else '✗'}, "
              f"AlienVault: {'✓' if self.api_keys['alienvault'] else '✗'}")

    def _connect_db(self):
        """Create a database connection"""
        return mysql.connector.connect(**self.db_config)
    
    def _ensure_threat_intel_tables(self):
        """Create the threat intelligence tables if they don't exist"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            # Create indicators table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_indicators (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    indicator_type ENUM('ip', 'url', 'domain', 'hash') NOT NULL,
                    indicator_value VARCHAR(255) NOT NULL,
                    threat_type VARCHAR(100),
                    confidence FLOAT,
                    source VARCHAR(100),
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    metadata TEXT,
                    UNIQUE KEY (indicator_type, indicator_value)
                )
            """)
            
            # Create feeds table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_feeds (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    feed_name VARCHAR(100) NOT NULL,
                    feed_url VARCHAR(255) NOT NULL,
                    feed_type VARCHAR(50),
                    last_update TIMESTAMP,
                    update_interval INT DEFAULT 86400,
                    api_key VARCHAR(255),
                    enabled BOOLEAN DEFAULT TRUE,
                    UNIQUE KEY (feed_name)
                )
            """)
            
            # Insert default feeds
            default_feeds = [
                ("PhishTank", "https://checkurl.phishtank.com/checkurl/", "phishing", None, 3600, "", True),
                ("URLhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/", "malware", None, 3600, "", True),
                ("OpenPhish", "https://openphish.com/feed.txt", "phishing", None, 3600, "", True)
            ]
            
            for feed in default_feeds:
                try:
                    cursor.execute("""
                        INSERT IGNORE INTO threat_intel_feeds 
                        (feed_name, feed_url, feed_type, last_update, update_interval, api_key, enabled)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, feed)
                except mysql.connector.Error as err:
                    print(f"Error inserting feed {feed[0]}: {err}")
            
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error creating threat intelligence tables: {err}")
        finally:
            cursor.close()
            conn.close()
    
    def add_indicator(self, indicator_type, indicator_value, threat_type=None, 
                     confidence=None, source=None, metadata=None):
        """Add a new threat indicator to the database with deadlock handling"""
        max_attempts = 3
        attempt = 0
        
        while attempt < max_attempts:
            conn = self._connect_db()
            cursor = conn.cursor()
            
            try:
                # Start transaction
                conn.start_transaction()
                
                # First check if indicator exists
                cursor.execute(
                    "SELECT id FROM threat_intel_indicators WHERE indicator_type = %s AND indicator_value = %s",
                    (indicator_type, indicator_value)
                )
                exists = cursor.fetchone()
                
                if exists:
                    # Update existing record
                    query = """
                        UPDATE threat_intel_indicators SET
                        threat_type = COALESCE(%s, threat_type),
                        confidence = COALESCE(%s, confidence),
                        last_seen = NOW(),
                        metadata = COALESCE(%s, metadata),
                        source = COALESCE(%s, source)
                        WHERE id = %s
                    """
                    cursor.execute(query, (
                        threat_type, 
                        confidence,
                        json.dumps(metadata) if metadata else None,
                        source,
                        exists[0]
                    ))
                else:
                    # Insert new record
                    query = """
                        INSERT INTO threat_intel_indicators
                        (indicator_type, indicator_value, threat_type, confidence, source, first_seen, metadata)
                        VALUES (%s, %s, %s, %s, %s, NOW(), %s)
                    """
                    cursor.execute(query, (
                        indicator_type, indicator_value, threat_type, confidence, source, 
                        json.dumps(metadata) if metadata else None
                    ))
                    
                # Commit transaction
                conn.commit()
                return cursor.lastrowid
                
            except mysql.connector.Error as err:
                # Check for deadlock error
                if err.errno == 1213:  # Deadlock error code
                    attempt += 1
                    print(f"Deadlock detected (attempt {attempt}/{max_attempts}), retrying...")
                    time.sleep(0.5 * attempt)  # Exponential backoff
                    conn.rollback()
                else:
                    print(f"Database error adding threat indicator: {err}")
                    return None
            finally:
                cursor.close()
                conn.close()
                
        print(f"Failed to add indicator after {max_attempts} attempts due to persistent deadlocks")
        return None
    
    def _extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if not domain:
                if '/' in url:
                    domain = url.split('/')[0]
                else:
                    domain = url
            return domain
        except:
            return url
            
    def _guess_indicator_type(self, indicator):
        """Determine the type of indicator"""
        # Check if it's an IP
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(indicator):
            return 'ip'
            
        # Check if it's a URL
        if indicator.startswith(('http://', 'https://')):
            return 'url'
            
        # Check if it's a domain
        domain_pattern = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
        if '.' in indicator and domain_pattern.match(indicator.lower()):
            return 'domain'
            
        # Check if it's a hash (MD5, SHA1, SHA256)
        md5_pattern = re.compile(r'^[a-f0-9]{32}$')
        sha1_pattern = re.compile(r'^[a-f0-9]{40}$')
        sha256_pattern = re.compile(r'^[a-f0-9]{64}$')
        
        if md5_pattern.match(indicator.lower()) or sha1_pattern.match(indicator.lower()) or sha256_pattern.match(indicator.lower()):
            return 'hash'
            
        # Default to URL for other indicators
        return 'url'
    
    def check_indicator(self, indicator_value):
        """Check if an indicator exists in the threat intel database or via VirusTotal"""
        # Check cache first
        if indicator_value in self.cache:
            if datetime.datetime.now() - self.cache[indicator_value]['timestamp'] < datetime.timedelta(hours=1):
                return self.cache[indicator_value]['data']

        conn = self._connect_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Determine indicator type
            indicator_type = self._guess_indicator_type(indicator_value)
            
            query = """
                SELECT * FROM threat_intel_indicators
                WHERE indicator_value = %s OR indicator_value LIKE %s
            """
            
            # Handle domains vs URLs
            if indicator_type == 'url':
                domain = self._extract_domain(indicator_value)
                cursor.execute(query, (indicator_value, f"%{domain}%"))
            else:
                cursor.execute(query, (indicator_value, f"%{indicator_value}%"))
                
            result = cursor.fetchone()
            
            # If found in database, cache and return it
            if result:
                self.cache[indicator_value] = {
                    'data': result,
                    'timestamp': datetime.datetime.now()
                }
                return result
            
            # Not found in database, check with VirusTotal API
            if self.api_keys.get('virustotal') and indicator_type in ['url', 'domain']:
                print(f"Checking {indicator_value} against VirusTotal...")
                vt_result = self.check_virustotal(indicator_value)
                if vt_result:
                    # Formatting to match our database structure for consistent return values
                    result = {
                        'indicator_type': indicator_type,
                        'indicator_value': indicator_value,
                        'threat_type': vt_result['threat_type'],
                        'confidence': vt_result['confidence'],
                        'source': 'VirusTotal',
                        'first_seen': datetime.datetime.now(),
                        'last_seen': datetime.datetime.now(),
                        'metadata': json.dumps({
                            'malicious': vt_result['malicious'],
                            'suspicious': vt_result['suspicious'],
                            'harmless': vt_result['harmless'],
                            'vendors': vt_result['vendors']
                        })
                    }
                    
                    # Cache the result
                    self.cache[indicator_value] = {
                        'data': result,
                        'timestamp': datetime.datetime.now()
                    }
                    return result
            
            # Not found anywhere
            return None
            
        except mysql.connector.Error as err:
            print(f"Database error checking threat indicator: {err}")
            return None
        finally:
            cursor.close()
            conn.close()
    
    def check_virustotal(self, url):
        """Check URL against VirusTotal API using your API key"""
        if not self.api_keys['virustotal']:
            return None
        
        try:
            # For URL scanning, we need to submit the URL for analysis first
            # Convert URL to base64 format required by VT API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_keys['virustotal']
            }
            
            # First check if URL has already been analyzed
            check_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(check_url, headers=headers)
            
            # If we get a 404, the URL hasn't been analyzed yet
            if response.status_code == 404:
                # Submit URL for analysis
                scan_url = "https://www.virustotal.com/api/v3/urls"
                payload = {"url": url}
                response = requests.post(scan_url, headers=headers, data=payload)
                
                if response.status_code != 200:
                    print(f"Error submitting URL to VirusTotal: {response.status_code}")
                    return None
                    
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                
                # Wait a bit for analysis to complete
                time.sleep(5)
                
                # Check analysis results
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                response = requests.get(analysis_url, headers=headers)
            
            # Process results
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0) + stats.get('undetected', 0)
                
                # Extract more detailed results
                results = attributes.get('results', {})
                vendors = []
                for engine, result in results.items():
                    if result.get('category') == 'malicious':
                        vendors.append(f"{engine}: {result.get('result', 'malicious')}")
                
                if malicious > 0 or suspicious > 0:
                    # Add to our threat intel database
                    metadata = {
                        'vt_analysis_id': data.get('data', {}).get('id', ''),
                        'vt_vendors': vendors[:10],  # First 10 vendors that flagged it
                        'vt_total_vendors': len(results),
                        'analysis_date': attributes.get('date')
                    }
                    
                    indicator_type = 'url'
                    threat_type = 'malware' if malicious > suspicious else 'suspicious'
                    confidence = min(1.0, (malicious * 0.1 + suspicious * 0.05) / len(results))
                    
                    # Save to our database
                    self.add_indicator(
                        indicator_type, url, threat_type, 
                        confidence, 'VirusTotal', metadata
                    )
                    
                    return {
                        'malicious': malicious,
                        'suspicious': suspicious,
                        'harmless': harmless,
                        'threat_type': threat_type,
                        'source': 'VirusTotal',
                        'confidence': confidence,
                        'vendors': vendors[:5]  # Show first 5 vendors
                    }
            
            return None
        
        except Exception as e:
            print(f"Error checking VirusTotal: {e}")
            return None
    
    def update_feeds(self):
        """Update all enabled threat intelligence feeds with locking"""
        # Prevent multiple threads from updating feeds simultaneously
        try:
            if not self.update_lock.acquire(blocking=False):
                print("Feed update already in progress, skipping this run")
                return
            
            try:
                conn = self._connect_db()
                cursor = conn.cursor(dictionary=True)
                
                try:
                    cursor.execute("SELECT * FROM threat_intel_feeds WHERE enabled = TRUE")
                    feeds = cursor.fetchall()
                    
                    for feed in feeds:
                        try:
                            self._update_feed(feed)
                            
                            # Update last_update timestamp
                            update_query = "UPDATE threat_intel_feeds SET last_update = NOW() WHERE id = %s"
                            cursor.execute(update_query, (feed['id'],))
                            conn.commit()
                        except Exception as e:
                            print(f"Error updating feed {feed.get('feed_name', 'unknown')}: {e}")
                        
                except mysql.connector.Error as err:
                    print(f"Database error updating threat feeds: {err}")
                finally:
                    cursor.close()
                    conn.close()
            finally:
                # Always release the lock
                self.update_lock.release()
        except Exception as e:
            print(f"Critical error in update_feeds: {e}")
    
    def _update_feed(self, feed):
        """Update a specific threat intelligence feed"""
        print(f"Updating feed: {feed['feed_name']}")
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                if feed['feed_name'] == 'PhishTank':
                    self._update_phishtank(feed)
                elif feed['feed_name'] == 'URLhaus':
                    self._update_urlhaus(feed)
                elif feed['feed_name'] == 'OpenPhish':
                    self._update_openphish(feed)
                
                # If successful, break the retry loop
                break
                
            except Exception as e:
                retry_count += 1
                print(f"Error updating feed {feed['feed_name']} (attempt {retry_count}): {e}")
                time.sleep(1)  # Wait before retrying
                
                if retry_count >= max_retries:
                    print(f"Failed to update feed {feed['feed_name']} after {max_retries} attempts")
    
    def _update_phishtank(self, feed):
        """Update from PhishTank API"""
        try:
            # PhishTank doesn't require API key for the downloadable database
            url = "http://data.phishtank.com/data/online-valid.json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                phishing_data = response.json()
                # Process only the first 50 entries to avoid overwhelming the database
                for entry in phishing_data[:50]:
                    phish_url = entry.get('url')
                    if phish_url:
                        metadata = {
                            "verified": entry.get('verified', 'unknown'),
                            "verification_time": entry.get('verification_time', ''),
                            "target": entry.get('target', 'Unknown')
                        }
                        self.add_indicator('url', phish_url, 'phishing', 0.95, 'PhishTank', metadata)
                print(f"Added {min(50, len(phishing_data))} entries from PhishTank")
            else:
                print(f"PhishTank API error: {response.status_code}")
        except Exception as e:
            print(f"Error updating from PhishTank: {e}")

    def _update_urlhaus(self, feed):
        """Update from URLhaus API"""
        if not self.api_keys.get('virustotal'):
            print("No VT API key available, using simulated URLhaus data")
            # Fall back to simulated data if no API key
            self._simulated_urlhaus_update()
            return
            
        try:
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                urls = data.get('urls', [])
                # Process only the first 30 entries
                for entry in urls[:30]:
                    malware_url = entry.get('url')
                    if malware_url:
                        threat_type = entry.get('threat', 'malware')
                        tags = entry.get('tags', [])
                        metadata = {
                            "malware_type": threat_type,
                            "tags": tags,
                            "added_date": entry.get('date_added')
                        }
                        self.add_indicator('url', malware_url, threat_type, 0.9, 'URLhaus', metadata)
                        time.sleep(0.2)  # Small delay to avoid database contention
                print(f"Added {min(30, len(urls))} entries from URLhaus")
            else:
                print(f"URLhaus API error: {response.status_code}")
        except Exception as e:
            print(f"Error updating from URLhaus: {e}")
            # Fall back to simulated data on error
            self._simulated_urlhaus_update()
    
    def _update_openphish(self, feed):
        """Update from OpenPhish feed"""
        try:
            url = feed['feed_url']
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                # OpenPhish feed is a plain text file with one URL per line
                phish_urls = response.text.strip().split('\n')
                count = 0
                
                # Process only first 50 URLs
                for phish_url in phish_urls[:50]:
                    if phish_url.startswith(('http://', 'https://')):
                        metadata = {
                            "source": "OpenPhish",
                            "detectionDate": datetime.datetime.now().isoformat()
                        }
                        self.add_indicator('url', phish_url, 'phishing', 0.85, 'OpenPhish', metadata)
                        count += 1
                
                print(f"Added {count} entries from OpenPhish")
            else:
                print(f"OpenPhish API error: {response.status_code}")
        except Exception as e:
            print(f"Error updating from OpenPhish: {e}")

    def _update_alienvault(self, feed):
        """Update from AlienVault OTX API"""
        if not self.api_keys.get('alienvault'):
            print("No AlienVault API key available, skipping")
            return
            
        try:
            headers = {
                'X-OTX-API-KEY': self.api_keys['alienvault']
            }
            # Get recent pulse activity
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                count = 0
                
                # Process pulses
                for pulse in pulses[:10]:  # Limit to 10 pulses
                    for indicator in pulse.get('indicators', [])[:5]:  # Limit to 5 indicators per pulse
                        indicator_type = indicator.get('type')
                        indicator_value = indicator.get('indicator')
                        
                        # Map OTX types to our types
                        if indicator_type in ['domain', 'hostname']:
                            our_type = 'domain'
                        elif indicator_type == 'URL':
                            our_type = 'url'
                        elif indicator_type in ['IPv4', 'IPv6']:
                            our_type = 'ip'
                        elif indicator_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                            our_type = 'hash'
                        else:
                            continue  # Skip unsupported types
                        
                        metadata = {
                            "pulse_name": pulse.get('name'),
                            "description": pulse.get('description'),
                            "tags": pulse.get('tags', [])
                        }
                        
                        self.add_indicator(
                            our_type, indicator_value,
                            pulse.get('malware_families', ['unknown'])[0], 
                            float(indicator.get('expiration', 0)) / 10,  # Normalize to 0-1
                            'AlienVault OTX', metadata
                        )
                        count += 1
                        time.sleep(0.2)  # Small delay
                        
                print(f"Added {count} indicators from AlienVault OTX")
            else:
                print(f"AlienVault API error: {response.status_code}")
        except Exception as e:
            print(f"Error updating from AlienVault: {e}")
    
    def _simulated_urlhaus_update(self):
        """Simulated update from URLhaus when API is unavailable"""
        malware_urls = [
            "http://malware-distribution.example.com/payload.exe",
            "https://drive-by-download.example.org/exploit.js",
            "http://trojan-hosting.example.net/update.zip"
        ]
        for url in malware_urls:
            metadata = {
                "malware_type": "trojan",
                "tags": ["exe", "botnet", "banking"],
                "simulated": True
            }
            self.add_indicator('url', url, 'malware', 0.9, 'URLhaus (Simulated)', metadata)
            time.sleep(0.2)
    
    def start_background_updates(self, interval=3600):
        """Start background thread for feed updates with better Streamlit compatibility"""
        if self.running and self.update_thread and self.update_thread.is_alive():
            print("Threat intelligence updates already running")
            return
            
        # Define update_loop inside with proper exception handling
        def update_loop():
            try:
                # Run an initial update after a short delay to avoid startup contention
                time.sleep(5)
                
                while self.running:
                    try:
                        self.update_feeds()
                    except Exception as e:
                        print(f"Error in threat feed update: {e}")
                        # Add a small delay if there was an error to avoid tight loops
                        time.sleep(10)
                    
                    # Use time.sleep() for the interval rather than a loop
                    time.sleep(interval)
            except Exception as e:
                print(f"Fatal error in threat intelligence update thread: {e}")

        # Reset state and start fresh
        if self.update_thread and self.update_thread.is_alive():
            try:
                self.running = False
                self.update_thread.join(timeout=2)
            except Exception as e:
                print(f"Error stopping existing thread: {e}")
                
        self.running = True
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()
        print(f"Started background threat intel updates every {interval} seconds")
    
    def stop_background_updates(self):
        """Stop background thread for feed updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
            print("Stopped background threat intel updates")

# In your app.py main function
def main():
    # Initialize components
    threat_intel = ThreatIntelligence()
    
    # Set up the UI and other components first
    # ...
    
    # Only start background processes AFTER the UI is ready
    # and with exception handling
    try:
        threat_intel.start_background_updates(interval=3600)
    except Exception as e:
        st.error(f"Error starting threat intelligence updates: {e}")
        # Continue app execution without background updates