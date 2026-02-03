import requests
import time
import mysql.connector
import re
from urllib.parse import urlparse, unquote
import logging

# Note: For actual implementation, you'd need:
# pip install selenium webdriver-manager beautifulsoup4

class URLAnalyzer:
    def __init__(self, db_config=None):
        self.db_config = db_config or {
            'host': 'localhost',
            'user': 'root',
            'password': 'Dhruv001@',
            'database': 'cybersecurity_db'
        }
        self._ensure_analysis_table()
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 
            'is.gd', 'cli.gs', 'pic.gd', 'DwarfURL.com',
            'ow.ly', 'yfrog', 'migre.me', 'ff.im', 'tiny.cc',
            'url4.eu', 'tr.im', 'twit.ac', 'su.pr', 'twurl.nl',
            'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm'
        ]
        
    def _connect_db(self):
        """Create a database connection"""
        return mysql.connector.connect(**self.db_config)
    
    def _ensure_analysis_table(self):
        """Create the url_analysis_results table if it doesn't exist"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS url_analysis_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    original_url VARCHAR(255) NOT NULL,
                    resolved_url VARCHAR(255),
                    is_obfuscated BOOLEAN DEFAULT FALSE,
                    has_js_redirects BOOLEAN DEFAULT FALSE,
                    has_hidden_elements BOOLEAN DEFAULT FALSE,
                    has_fake_forms BOOLEAN DEFAULT FALSE,
                    has_suspicious_scripts BOOLEAN DEFAULT FALSE,
                    behavior_details TEXT,
                    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error creating url_analysis_results table: {err}")
        finally:
            cursor.close()
            conn.close()
            
    def expand_url(self, url):
        """Expand shortened URLs"""
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Check if this is a URL shortener
        domain = urlparse(url).netloc
        if domain not in self.url_shorteners:
            return url, False
            
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            expanded_url = response.url
            return expanded_url, expanded_url != url
        except Exception as e:
            print(f"Error expanding URL {url}: {e}")
            return url, False
            
    def analyze_javascript_behavior(self, url):
        """
        Simulated JS behavior analysis. 
        In a real implementation, this would use Selenium or similar.
        """
        # This is a simulation - in real code, use Selenium WebDriver
        behaviors = {
            'redirects': False,
            'hidden_elements': False,
            'fake_forms': False,
            'suspicious_scripts': False,
            'details': []
        }
        
        # Simulate behavior detection based on URL patterns
        if any(x in url.lower() for x in ['redirect', 'url=', 'goto=']):
            behaviors['redirects'] = True
            behaviors['details'].append("Detected URL parameter suggesting client-side redirect")
            
        if any(x in url.lower() for x in ['login', 'signin', 'account']):
            behaviors['fake_forms'] = True
            behaviors['details'].append("Potential fake login form detected in URL path")
            
        if any(x in url.lower() for x in ['hidden', 'display=none', 'visibility']):
            behaviors['hidden_elements'] = True
            behaviors['details'].append("URL suggests hidden element manipulation")
            
        if any(x in url.lower() for x in ['eval', 'script', 'js', 'javascript']):
            behaviors['suspicious_scripts'] = True
            behaviors['details'].append("URL contains terms suggesting dynamic script execution")
            
        # In a real implementation, we would use headless browser to detect:
        # - Actual DOM modification
        # - Form submissions to suspicious endpoints
        # - Hidden iframes
        # - Eval or other dynamic code execution
            
        return behaviors
        
    def deobfuscate_url(self, url):
        """De-obfuscate encoded URLs"""
        # Handle URL encoding
        decoded_url = unquote(url)
        
        # Handle hex encoding
        hex_pattern = re.compile(r'%([0-9a-fA-F]{2})')
        while re.search(hex_pattern, decoded_url):
            decoded_url = re.sub(hex_pattern, 
                               lambda m: chr(int(m.group(1), 16)), 
                               decoded_url)
        
        # Handle obfuscated URL patterns
        if 'http' in decoded_url[5:]:  # URL within URL
            inner_url_match = re.search(r'(https?://[^\s"\']+)', decoded_url[5:])
            if inner_url_match:
                return inner_url_match.group(0)
                
        return decoded_url
        
    def analyze_url(self, url):
        """Complete URL analysis"""
        results = {
            'original_url': url,
            'resolved_url': url,
            'is_obfuscated': False,
            'has_js_redirects': False,
            'has_hidden_elements': False, 
            'has_fake_forms': False,
            'has_suspicious_scripts': False,
            'behavior_details': ''
        }
        
        # Step 1: Expand shortened URLs
        expanded_url, was_shortened = self.expand_url(url)
        if was_shortened:
            results['is_obfuscated'] = True
            results['behavior_details'] += f"URL was shortened: {url} -> {expanded_url}\n"
        
        # Step 2: Decode any URL encoding/obfuscation
        deobfuscated_url = self.deobfuscate_url(expanded_url)
        results['resolved_url'] = deobfuscated_url
        
        if deobfuscated_url != expanded_url:
            results['is_obfuscated'] = True
            results['behavior_details'] += f"URL was obfuscated: {expanded_url} -> {deobfuscated_url}\n"
        
        # Step 3: Analyze JavaScript behavior
        behavior = self.analyze_javascript_behavior(deobfuscated_url)
        
        results['has_js_redirects'] = behavior['redirects']
        results['has_hidden_elements'] = behavior['hidden_elements']
        results['has_fake_forms'] = behavior['fake_forms']
        results['has_suspicious_scripts'] = behavior['suspicious_scripts']
        results['behavior_details'] += '\n'.join(behavior['details'])
        
        # Store results in database
        self._save_analysis_results(results)
        
        return results
    
    def _save_analysis_results(self, results):
        """Save analysis results to database"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            query = """
                INSERT INTO url_analysis_results 
                (original_url, resolved_url, is_obfuscated, has_js_redirects,
                 has_hidden_elements, has_fake_forms, has_suspicious_scripts, behavior_details)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (
                results['original_url'],
                results['resolved_url'],
                results['is_obfuscated'],
                results['has_js_redirects'],
                results['has_hidden_elements'],
                results['has_fake_forms'],
                results['has_suspicious_scripts'],
                results['behavior_details']
            ))
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Database error saving URL analysis results: {err}")
        finally:
            cursor.close()
            conn.close()