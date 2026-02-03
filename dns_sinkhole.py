import mysql.connector
import socket
import threading
import struct
import os
import subprocess
import platform
from datetime import datetime
from urllib.parse import urlparse
import http.server
import socketserver
from threading import Thread
import ssl

class DNSSinkhole:
    def __init__(self, db_config=None):
        self.db_config = db_config or {
            'host': 'localhost',
            'user': 'root',
            'password': 'Dhruv001@',
            'database': 'cybersecurity_db'
        }
        self.sinkhole_ip = "127.0.0.1"
        self.blocked_servers = {}
        self._ensure_sinkhole_table()
        self._start_comprehensive_blocking()
        
    def _connect_db(self):
        """Create a database connection"""
        return mysql.connector.connect(**self.db_config)

    def _start_comprehensive_blocking(self):
        """Start comprehensive blocking system"""
        print("🛡️ Starting Comprehensive DNS Sinkhole System...")
        
        # Start HTTP servers on multiple ports
        self._start_http_servers()
        
        # Update system DNS settings
        self._update_system_dns()
        
        print("✅ DNS Sinkhole system fully activated")

    def _start_http_servers(self):
        """Start HTTP servers on multiple ports to catch redirected traffic"""
        # Use non-privileged ports to avoid permission issues
        ports = [8080, 8081, 8082, 8083, 8443, 9000, 9001, 9002]
        
        for port in ports:
            self._start_blocking_server(port)

    def _start_blocking_server(self, port):
        """Start a blocking server on a specific port"""
        try:
            class ComprehensiveSinkholeHandler(http.server.BaseHTTPRequestHandler):
                def __init__(self, *args, sinkhole_instance=None, **kwargs):
                    self.sinkhole = sinkhole_instance
                    super().__init__(*args, **kwargs)

                def do_GET(self):
                    self._handle_request()

                def do_POST(self):
                    self._handle_request()

                def do_HEAD(self):
                    self._handle_request()

                def do_OPTIONS(self):
                    self._handle_request()

                def do_PUT(self):
                    self._handle_request()

                def do_DELETE(self):
                    self._handle_request()

                def _handle_request(self):
                    """Handle any HTTP request"""
                    try:
                        # Extract domain information
                        host_header = self.headers.get('Host', 'unknown')
                        domain = host_header.split(':')[0] if host_header else 'unknown'
                        client_ip = self.client_address[0]
                        request_path = self.path
                        request_method = self.command
                        
                        print(f"🌐 {request_method}: {client_ip} → {host_header}{request_path}")
                        
                        # Always serve blocking page for sinkholed domains
                        if self.sinkhole and self.sinkhole._is_domain_sinkholed(domain):
                            print(f"🛑 SINKHOLE BLOCK: {domain}{request_path} from {client_ip}")
                            self.sinkhole._log_blocked_request(domain, client_ip, request_path, request_method)
                            self.sinkhole._update_sinkhole_stats('blocked_request')  # Add this line
                            self._serve_sinkhole_page(domain, client_ip, request_path, request_method)
                        else:
                            print(f"ℹ️ Non-sinkholed domain: {domain}")
                            self._serve_info_page(domain, client_ip, request_path)
                        
                    except Exception as e:
                        print(f"❌ Error handling request: {e}")
                        self._serve_error_page()

                def _serve_sinkhole_page(self, domain, client_ip, request_path, method):
                    """Serve the sinkhole blocking page"""
                    try:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html; charset=utf-8')
                        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                        self.send_header('Pragma', 'no-cache')
                        self.send_header('Expires', '0')
                        self.send_header('X-Sinkhole', 'BLOCKED')
                        self.end_headers()
                        
                        # Get sinkhole details
                        sinkhole_info = self.sinkhole._get_sinkhole_info(domain)
                        
                        blocking_page = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <title>🛑 DOMAIN BLOCKED - Security Protection Active</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #000000 0%, #1a0000 50%, #330000 100%); 
            color: #ff0000; 
            text-align: center; 
            padding: 20px; 
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            max-width: 900px;
            width: 100%;
            background: rgba(20, 0, 0, 0.95);
            border: 3px solid #ff0000;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 0 50px rgba(255, 0, 0, 0.5);
            animation: pulse 2s infinite;
        }}
        .warning-icon {{
            font-size: 8em;
            color: #ff0000;
            margin-bottom: 20px;
            animation: rotate 3s linear infinite;
        }}
        h1 {{
            color: #ff3333;
            font-size: 3em;
            margin-bottom: 20px;
            text-shadow: 0 0 20px rgba(255, 0, 0, 0.8);
        }}
        .alert {{
            background: rgba(255, 0, 0, 0.2);
            border: 2px solid #ff3333;
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            font-size: 1.3em;
        }}
        .details {{
            background: rgba(0, 0, 0, 0.7);
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            text-align: left;
        }}
        .detail-row {{
            margin: 15px 0;
            padding: 10px;
            background: rgba(255, 0, 0, 0.1);
            border-radius: 8px;
        }}
        .label {{ font-weight: bold; color: #ff6666; }}
        .value {{ 
            color: #ffaaaa; 
            font-family: monospace; 
            background: rgba(0, 0, 0, 0.5);
            padding: 5px;
            border-radius: 5px;
        }}
        .actions {{
            margin: 40px 0;
        }}
        .btn {{
            background: linear-gradient(45deg, #ff0000, #ff3333);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            margin: 10px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }}
        .btn:hover {{
            background: linear-gradient(45deg, #ff3333, #ff6666);
        }}
        @keyframes pulse {{
            0%, 100% {{ box-shadow: 0 0 50px rgba(255, 0, 0, 0.5); }}
            50% {{ box-shadow: 0 0 100px rgba(255, 0, 0, 0.8); }}
        }}
        @keyframes rotate {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-icon">🛡️</div>
        <h1>DOMAIN BLOCKED BY SINKHOLE</h1>
        
        <div class="alert">
            <strong>🚨 SECURITY ALERT 🚨</strong><br>
            This domain has been identified as malicious and blocked by the DNS sinkhole system.
        </div>
        
        <div class="details">
            <h3 style="color: #ff6666; margin-bottom: 20px;">🔍 Block Details</h3>
            <div class="detail-row">
                <span class="label">Blocked Domain:</span>
                <span class="value">{domain}</span>
            </div>
            <div class="detail-row">
                <span class="label">Requested Path:</span>
                <span class="value">{request_path}</span>
            </div>
            <div class="detail-row">
                <span class="label">Request Method:</span>
                <span class="value">{method}</span>
            </div>
            <div class="detail-row">
                <span class="label">Client IP:</span>
                <span class="value">{client_ip}</span>
            </div>
            <div class="detail-row">
                <span class="label">Block Time:</span>
                <span class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="detail-row">
                <span class="label">Block Reason:</span>
                <span class="value">{sinkhole_info.get('reason', 'Malicious domain detected')}</span>
            </div>
            <div class="detail-row">
                <span class="label">Sinkhole Server:</span>
                <span class="value">{self.sinkhole.sinkhole_ip}:{self.server.server_port}</span>
            </div>
        </div>
        
        <div class="alert">
            <strong>⚠️ PROTECTION ACTIVE</strong><br>
            This domain has been automatically redirected to a safe sinkhole server.<br>
            Your system and data are protected from potential threats.
        </div>
        
        <div class="actions">
            <button class="btn" onclick="window.history.back()">← Go Back</button>
            <button class="btn" onclick="window.close()">✕ Close Tab</button>
            <a href="https://google.com" class="btn">🏠 Safe Search</a>
        </div>
        
        <div style="margin-top: 40px; font-size: 0.9em; color: #ff9999;">
            <p><strong>DNS Sinkhole Protection System</strong></p>
            <p>All malicious domains are automatically blocked and logged for security analysis.</p>
            <p><em>If you believe this is an error, contact your system administrator.</em></p>
        </div>
    </div>
    
    <script>
        console.log('🛡️ DNS SINKHOLE BLOCK ACTIVE');
        console.log('Domain: {domain}');
        console.log('Reason: {sinkhole_info.get("reason", "Security block")}');
        
        // Prevent bypass attempts
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'F12' || (e.ctrlKey && e.shiftKey)) {{
                e.preventDefault();
            }}
        }});
    </script>
</body>
</html>
                        """
                        
                        self.wfile.write(blocking_page.encode('utf-8'))
                        
                    except Exception as e:
                        print(f"❌ Error serving sinkhole page: {e}")
                        self._serve_error_page()

                def _serve_info_page(self, domain, client_ip, request_path):
                    """Serve info page for non-blocked domains"""
                    try:
                        self.send_response(404)
                        self.send_header('Content-type', 'text/html; charset=utf-8')
                        self.end_headers()
                        
                        info_page = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Sinkhole Server - Domain Not Blocked</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f0f0f0; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Sinkhole Server</h1>
        <p><strong>Domain:</strong> {domain}</p>
        <p><strong>Status:</strong> Not currently blocked</p>
        <p>This server monitors malicious domains. The requested domain is not in our threat database.</p>
    </div>
</body>
</html>
                        """
                        self.wfile.write(info_page.encode('utf-8'))
                    except:
                        self._serve_error_page()

                def _serve_error_page(self):
                    """Serve error page"""
                    try:
                        self.send_response(500)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>Server Error</h1></body></html>")
                    except:
                        pass

                def log_message(self, format, *args):
                    pass

            # Start server thread
            def start_server(port_num):
                try:
                    # Check if port is available
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', port_num))
                    sock.close()
                    
                    if result == 0:
                        print(f"⚠️ Port {port_num} already in use")
                        return

                    # Create handler
                    handler = lambda *args, **kwargs: ComprehensiveSinkholeHandler(*args, sinkhole_instance=self, **kwargs)
                    
                    class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
                        allow_reuse_address = True
                        daemon_threads = True
                    
                    with ThreadingTCPServer(("0.0.0.0", port_num), handler) as httpd:
                        self.blocked_servers[port_num] = httpd
                        print(f"🛡️ Sinkhole server active on port {port_num}")
                        httpd.serve_forever()
                        
                except Exception as e:
                    print(f"❌ Error starting server on port {port_num}: {e}")

            # Start in background thread
            server_thread = Thread(target=start_server, args=(port,), daemon=True)
            server_thread.start()
            
        except Exception as e:
            print(f"❌ Error setting up server for port {port}: {e}")

    def add_domain_to_sinkhole(self, domain, user_id, reason="Malicious URL detected"):
        """Add a domain to the sinkhole with immediate DNS blocking"""
        # Extract domain from URL if needed
        if domain.startswith('http'):
            domain = urlparse(domain).netloc
        
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            base_domain = domain[4:]
        else:
            base_domain = domain
            
        print(f"🔧 Adding {base_domain} to comprehensive sinkhole...")
        
        # Add to database
        success = self._add_to_database(base_domain, user_id, reason)
        if not success:
            return False
        
        # Update stats for manual additions (if not auto-detected)
        if "AUTO-DETECTED" not in reason:
            self._update_sinkhole_stats('manual_added')
        
        # CRITICAL: Add to hosts file for immediate DNS redirection
        print("🔐 Adding to hosts file (requires admin privileges)...")
        hosts_success = self._add_to_hosts_file_force(base_domain)
        
        # Force DNS cache flush
        flush_success = self._force_dns_flush()
        
        # Verify the sinkhole is working
        verification = self._verify_sinkhole_active(base_domain)
        
        if verification['working']:
            print(f"\n✅ SUCCESS: {base_domain} is now fully sinkholed!")
            print(f"   → DNS Resolution: All variants → {self.sinkhole_ip}")
            print(f"   → HTTP traffic: Blocked by sinkhole servers")
            print(f"   → HTTPS traffic: Certificate warnings will appear")
            print(f"   → Active servers: {list(self.blocked_servers.keys())}")
        else:
            print(f"\n⚠️ PARTIAL SUCCESS: {base_domain} added but some issues detected:")
            for check, status in verification.items():
                status_icon = '✅' if status else '❌'
                print(f"   → {check.replace('_', ' ').title()}: {status_icon}")
            
            # Provide troubleshooting steps
            print(f"\n🔧 TROUBLESHOOTING STEPS:")
            print(f"1. Restart your browser completely")
            print(f"2. Clear browser cache and cookies")
            print(f"3. Try accessing in Incognito/Private mode")
            print(f"4. Wait 30-60 seconds for DNS propagation")
            print(f"5. Test with: http://{base_domain} (not https://)")
        
        # Important user instructions
        print(f"\n📋 IMPORTANT NOTES:")
        print(f"• HTTPS sites may show certificate warnings - this is normal")
        print(f"• Browser cache may need manual clearing")
        print(f"• Incognito/Private browsing bypasses cached DNS")
        print(f"• Some browsers use DNS-over-HTTPS which may bypass blocking")
        print(f"• The sinkhole is working if you see the red blocking page")
        
        return True

    def _add_to_database(self, domain, user_id, reason):
        """Add domain to sinkhole database"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT id FROM sinkhole_logs WHERE domain = %s", (domain,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute("""
                    UPDATE sinkhole_logs 
                    SET reason = %s, blocked_at = NOW() 
                    WHERE id = %s
                """, (f"{reason} (updated)", existing[0]))
                conn.commit()
                print(f"✅ Updated database entry for {domain}")
            else:
                cursor.execute("""
                    INSERT INTO sinkhole_logs (user_id, domain, reason) 
                    VALUES (%s, %s, %s)
                """, (user_id, domain, reason))
                conn.commit()
                print(f"✅ Added database entry for {domain}")
            
            return True
                
        except mysql.connector.Error as err:
            print(f"❌ Database error: {err}")
            return False
        finally:
            cursor.close()
            conn.close()

    def _add_to_hosts_file_force(self, domain):
        """Force add domain to hosts file with comprehensive blocking"""
        hosts_path = '/etc/hosts'
        
        # Create multiple domain variants to block
        domain_variants = [
            domain,
            f"www.{domain}",
            f"m.{domain}",
            f"mobile.{domain}",
            f"*.{domain}"
        ]
        
        # Remove duplicates and clean up
        unique_domains = list(set(variant for variant in domain_variants if variant != f"www.www.{domain}"))
        
        try:
            # Check if entries already exist
            with open(hosts_path, 'r') as f:
                content = f.read()
            
            existing_entries = []
            new_entries = []
            
            for variant in unique_domains:
                if f"{self.sinkhole_ip} {variant}" not in content:
                    new_entries.append(variant)
                else:
                    existing_entries.append(variant)
            
            if existing_entries:
                print(f"✅ Already blocked: {', '.join(existing_entries)}")
            
            if not new_entries:
                print(f"✅ All variants of {domain} already in hosts file")
                return True
                
        except PermissionError:
            print(f"⚠️ Permission denied reading hosts file")
            # Continue to attempt writing
            new_entries = unique_domains

        # Prepare sinkhole entries with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        sinkhole_entries = []
        
        for variant in new_entries:
            sinkhole_entries.append(f"{self.sinkhole_ip} {variant}  # DNS Sinkhole - {timestamp}")
        
        # Try to write to hosts file
        try:
            with open(hosts_path, 'a') as f:
                f.write('\n')
                for entry in sinkhole_entries:
                    f.write(entry + '\n')
            
            print(f"✅ Added {len(sinkhole_entries)} domain variants to hosts file:")
            for variant in new_entries:
                print(f"   → {variant} → {self.sinkhole_ip}")
            return True
            
        except PermissionError:
            print(f"❌ Permission denied. Attempting sudo method...")
            return self._add_to_hosts_with_sudo(sinkhole_entries)
        except Exception as e:
            print(f"❌ Hosts file error: {e}")
            return False

    def _add_to_hosts_with_sudo(self, entries):
        """Add entries to hosts file using sudo"""
        try:
            # Create a temporary file with the entries
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as tmp_file:
                for entry in entries:
                    tmp_file.write(entry + '\n')
                tmp_path = tmp_file.name
            
            # Use sudo to append to hosts file
            cmd = ['sudo', 'bash', '-c', f'cat {tmp_path} >> /etc/hosts']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Clean up temp file
            os.unlink(tmp_path)
            
            if result.returncode == 0:
                print(f"✅ Successfully added {len(entries)} entries using sudo")
                return True
            else:
                print(f"❌ Sudo command failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Sudo method failed: {e}")
            print("🔧 Manual fix required:")
            print("   Run the following commands in terminal:")
            for entry in entries:
                print(f"   echo '{entry}' | sudo tee -a /etc/hosts")
            print("   sudo dscacheutil -flushcache")
            print("   sudo killall -HUP mDNSResponder")
            return False

    def _force_dns_flush(self):
        """Force comprehensive DNS cache flush"""
        print("🔄 Performing comprehensive DNS cache flush...")
        
        # macOS specific commands
        macos_commands = [
            ['sudo', 'dscacheutil', '-flushcache'],
            ['sudo', 'killall', '-HUP', 'mDNSResponder'],
            ['sudo', 'discoveryutil', 'mdnsflushcache'],  # Older macOS versions
            ['sudo', 'discoveryutil', 'udnsflushcaches']   # Older macOS versions
        ]
        
        # Linux specific commands
        linux_commands = [
            ['sudo', 'systemctl', 'restart', 'systemd-resolved'],
            ['sudo', 'service', 'network-manager', 'restart'],
            ['sudo', 'systemctl', 'restart', 'NetworkManager'],
            ['sudo', '/etc/init.d/networking', 'restart']
        ]
        
        # Try all commands
        all_commands = macos_commands + linux_commands
        
        successful_commands = []
        for cmd in all_commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    successful_commands.append(' '.join(cmd))
                    print(f"✅ Successfully executed: {' '.join(cmd)}")
                else:
                    print(f"⚠️ Command failed: {' '.join(cmd)} - {result.stderr.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError) as e:
                print(f"⚠️ Command unavailable: {' '.join(cmd)}")
                continue
            except Exception as e:
                print(f"❌ Error executing {' '.join(cmd)}: {e}")
                continue
        
        # Additional network refresh
        try:
            # Restart network interfaces if possible
            subprocess.run(['sudo', 'ifconfig', 'en0', 'down'], capture_output=True, timeout=5)
            subprocess.run(['sudo', 'ifconfig', 'en0', 'up'], capture_output=True, timeout=5)
            print("✅ Network interface refreshed")
        except:
            pass
        
        if successful_commands:
            print(f"✅ DNS cache flush completed using: {', '.join(successful_commands)}")
        else:
            print("❌ All DNS flush commands failed - manual intervention may be needed")
        
        # Show browser cache clearing instructions
        print("\n🌐 IMPORTANT: Browser Cache Clearing Required:")
        print("   Chrome: Press Ctrl+Shift+Delete → Clear browsing data → Cached images")
        print("   Firefox: Press Ctrl+Shift+Delete → Clear cached web content")  
        print("   Safari: Develop menu → Empty Caches (enable Develop menu first)")
        print("   Edge: Press Ctrl+Shift+Delete → Clear cached data")
        print("\n💡 Alternative: Open the URL in an Incognito/Private window to bypass cache")
        
        return len(successful_commands) > 0

    def _verify_sinkhole_active(self, domain):
        """Verify that the sinkhole is working for a domain"""
        verification = {
            'database_entry': False,
            'hosts_file_entry': False,
            'dns_resolution': False,
            'server_active': False,
            'working': False
        }
        
        # Check database
        verification['database_entry'] = self._is_domain_sinkholed(domain)
        
        # Check hosts file
        try:
            with open('/etc/hosts', 'r') as f:
                content = f.read()
                verification['hosts_file_entry'] = f"{self.sinkhole_ip} {domain}" in content
        except:
            pass
        
        # Check DNS resolution
        try:
            resolved_ip = socket.gethostbyname(domain)
            verification['dns_resolution'] = (resolved_ip == self.sinkhole_ip)
        except:
            pass
        
        # Check if servers are active
        verification['server_active'] = len(self.blocked_servers) > 0
        
        # Overall status
        verification['working'] = all([
            verification['database_entry'],
            verification['hosts_file_entry'],
            verification['dns_resolution'],
            verification['server_active']
        ])
        
        return verification

    def _is_domain_sinkholed(self, domain):
        """Check if domain is in sinkhole database"""
        if not domain:
            return False
            
        # Always block test domains
        test_domains = [
            'secure.eicar.org',
            'eicar.org', 
            'malware-distribution.example.com',
            'phishing-test.example.com',
            'test-malware.com',
            'evil-site.net',
            'badsite.localhost'
        ]
        
        if domain in test_domains:
            return True
            
        # Check database
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sinkhole_logs WHERE domain = %s", (domain,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            return result[0] > 0
        except Exception as e:
            print(f"⚠️ Database check error: {e}")
            return False

    def _get_sinkhole_info(self, domain):
        """Get sinkhole information for a domain"""
        try:
            conn = self._connect_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT domain, reason, blocked_at 
                FROM sinkhole_logs 
                WHERE domain = %s 
                ORDER BY blocked_at DESC 
                LIMIT 1
            """, (domain,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            return result or {'reason': 'Domain blocked by security system'}
        except:
            return {'reason': 'Malicious domain detected'}

    def auto_add_malicious_domain(self, url, user_id, detection_details, severity_level):
        """Automatically add malicious domain to sinkhole"""
        domain = self._extract_domain_from_url(url)
        if not domain:
            print(f"❌ Could not extract domain from: {url}")
            return False
        
        reason = f"AUTO-DETECTED: Malicious content (Severity: {severity_level}/10, Malicious: {detection_details.get('malicious', 0)})"
        
        print(f"🤖 AUTO-SINKHOLE: {domain}")
        print(f"   → Original URL: {url}")
        print(f"   → Severity: {severity_level}/10")
        
        success = self.add_domain_to_sinkhole(domain, user_id, reason)
        
        if success:
            self._log_auto_addition(domain, url, detection_details, severity_level, user_id)
            self._update_sinkhole_stats('auto_added')  # Add this line
            print(f"✅ {domain} automatically sinkholed!")
        
        return success

    def _extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            import urllib.parse
            url = urllib.parse.unquote(url.strip())
            
            if url.startswith('%20'):
                url = url[3:]
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower().strip()
            
            if ':' in domain:
                domain = domain.split(':')[0]
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain if domain and '.' in domain else None
            
        except Exception as e:
            print(f"Error extracting domain: {e}")
            return None

    def _update_system_dns(self):
        """Update system DNS settings to ensure sinkhole effectiveness"""
        print("🔧 Configuring system DNS for sinkhole...")
        
        # This is handled by hosts file entries
        # Each domain added to sinkhole gets a hosts file entry
        print("✅ DNS configuration relies on hosts file entries")

    def test_sinkhole_comprehensive(self, domain):
        """Comprehensive test of sinkhole functionality"""
        print(f"\n🧪 COMPREHENSIVE SINKHOLE TEST: {domain}")
        print("=" * 60)
        
        # Test all components
        verification = self._verify_sinkhole_active(domain)
        
        print(f"1. Database Entry: {'✅' if verification['database_entry'] else '❌'}")
        print(f"2. Hosts File Entry: {'✅' if verification['hosts_file_entry'] else '❌'}")
        print(f"3. DNS Resolution: {'✅' if verification['dns_resolution'] else '❌'}")
        print(f"4. Servers Active: {'✅' if verification['server_active'] else '❌'}")
        print(f"5. Overall Status: {'✅ WORKING' if verification['working'] else '❌ NOT WORKING'}")
        
        if verification['dns_resolution']:
            try:
                resolved_ip = socket.gethostbyname(domain)
                print(f"   → {domain} resolves to {resolved_ip}")
            except:
                pass
        
        print(f"\n🌐 TEST INSTRUCTIONS:")
        print(f"   Open browser and go to: http://{domain}")
        print(f"   Expected: Should show sinkhole blocking page")
        print(f"   Active ports: {list(self.blocked_servers.keys())}")
        
        print(f"\n📋 TROUBLESHOOTING:")
        if not verification['database_entry']:
            print(f"   → Add {domain} to sinkhole database")
        if not verification['hosts_file_entry']:
            print(f"   → Run: echo '{self.sinkhole_ip} {domain}' | sudo tee -a /etc/hosts")
        if not verification['dns_resolution']:
            print(f"   → Run: sudo dscacheutil -flushcache")
        if not verification['server_active']:
            print(f"   → Restart application")
        
        print("=" * 60)
        return verification

    def get_sinkholed_domains(self, limit=50):
        """Get list of sinkholed domains"""
        conn = self._connect_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT domain, blocked_at, reason 
                FROM sinkhole_logs 
                ORDER BY blocked_at DESC 
                LIMIT %s
            """, (limit,))
            return cursor.fetchall()
        except mysql.connector.Error as err:
            print(f"Error getting domains: {err}")
            return []
        finally:
            cursor.close()
            conn.close()

    def _log_auto_addition(self, domain, original_url, detection_details, severity, user_id):
        """Log automatic additions"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_sinkhole_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain VARCHAR(255) NOT NULL,
                    original_url TEXT,
                    user_id INT,
                    severity_level INT,
                    malicious_score INT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                INSERT INTO auto_sinkhole_log 
                (domain, original_url, user_id, severity_level, malicious_score)
                VALUES (%s, %s, %s, %s, %s)
            """, (domain, original_url, user_id, severity, detection_details.get('malicious', 0)))
            
            conn.commit()
            
        except mysql.connector.Error as err:
            print(f"Error logging: {err}")
        finally:
            cursor.close()
            conn.close()

    def _log_blocked_request(self, domain, client_ip, request_path, method):
        """Log blocked requests"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain VARCHAR(255),
                    client_ip VARCHAR(45),
                    request_path TEXT,
                    request_method VARCHAR(10),
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                INSERT INTO blocked_requests (domain, client_ip, request_path, request_method)
                VALUES (%s, %s, %s, %s)
            """, (domain, client_ip, request_path, method))
            
            conn.commit()
            
        except mysql.connector.Error as err:
            print(f"Error logging request: {err}")
        finally:
            cursor.close()
            conn.close()

    def _ensure_sinkhole_table(self):
        """Create sinkhole table"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sinkhole_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    domain VARCHAR(255) NOT NULL,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason VARCHAR(255),
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)
            conn.commit()
        except mysql.connector.Error as err:
            print(f"Error creating table: {err}")
        finally:
            cursor.close()
            conn.close()

    def get_sinkhole_statistics(self):
        """Get comprehensive sinkhole statistics"""
        conn = self._connect_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Create stats table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sinkhole_stats (
                    id INT PRIMARY KEY DEFAULT 1,
                    total_domains INT DEFAULT 0,
                    auto_added INT DEFAULT 0,
                    manual_added INT DEFAULT 0,
                    blocked_requests INT DEFAULT 0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            
            # Get or create basic stats
            cursor.execute("SELECT * FROM sinkhole_stats WHERE id = 1")
            stats = cursor.fetchone()
            
            if not stats:
                # Initialize stats if none exist
                cursor.execute("""
                    INSERT INTO sinkhole_stats (id, total_domains, auto_added, manual_added, blocked_requests) 
                    VALUES (1, 0, 0, 0, 0)
                """)
                conn.commit()
                stats = {
                    'total_domains': 0, 
                    'auto_added': 0, 
                    'manual_added': 0, 
                    'blocked_requests': 0
                }
            
            # Get recent activity (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) as recent_additions 
                FROM sinkhole_logs 
                WHERE blocked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            recent = cursor.fetchone()
            stats['recent_additions'] = recent['recent_additions'] if recent else 0
            
            # Get actual count from sinkhole_logs table
            cursor.execute("SELECT COUNT(*) as actual_total FROM sinkhole_logs")
            actual = cursor.fetchone()
            stats['total_domains'] = actual['actual_total'] if actual else 0
            
            # Get top threat categories
            cursor.execute("""
                SELECT 
                    CASE 
                        WHEN reason LIKE '%phishing%' THEN 'Phishing'
                        WHEN reason LIKE '%malware%' THEN 'Malware'
                        WHEN reason LIKE '%AUTO-DETECTED%' THEN 'Auto-Detected'
                        WHEN reason LIKE '%defacement%' THEN 'Defacement'
                        ELSE 'Other'
                    END as category,
                    COUNT(*) as count
                FROM sinkhole_logs 
                GROUP BY category
                ORDER BY count DESC
            """)
            categories = cursor.fetchall()
            stats['threat_categories'] = categories
            
            # Get count of auto-added domains
            cursor.execute("""
                SELECT COUNT(*) as auto_count 
                FROM sinkhole_logs 
                WHERE reason LIKE '%AUTO-DETECTED%'
            """)
            auto_result = cursor.fetchone()
            stats['auto_added'] = auto_result['auto_count'] if auto_result else 0
            
            # Manual added is total minus auto
            stats['manual_added'] = stats['total_domains'] - stats['auto_added']
            
            # Get blocked requests count from blocked_requests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain VARCHAR(255),
                    client_ip VARCHAR(45),
                    request_path TEXT,
                    request_method VARCHAR(10),
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("SELECT COUNT(*) as blocked_count FROM blocked_requests")
            blocked_result = cursor.fetchone()
            stats['blocked_requests'] = blocked_result['blocked_count'] if blocked_result else 0
            
            return stats
            
        except mysql.connector.Error as err:
            print(f"Error getting sinkhole statistics: {err}")
            return {
                'total_domains': 0, 
                'auto_added': 0, 
                'manual_added': 0, 
                'blocked_requests': 0,
                'recent_additions': 0,
                'threat_categories': []
            }
        finally:
            cursor.close()
            conn.close()

    def get_auto_sinkhole_log(self, limit=50):
        """Get log of automatically sinkholed domains"""
        conn = self._connect_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Create table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_sinkhole_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain VARCHAR(255) NOT NULL,
                    original_url TEXT,
                    user_id INT,
                    severity_level INT,
                    malicious_score INT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Get auto-sinkhole log with user info
            cursor.execute("""
                SELECT asl.*, u.email 
                FROM auto_sinkhole_log asl
                LEFT JOIN users u ON asl.user_id = u.user_id
                ORDER BY asl.added_at DESC 
                LIMIT %s
            """, (limit,))
            
            results = cursor.fetchall()
            
            # If no auto_sinkhole_log entries, try to get from regular sinkhole_logs
            if not results:
                cursor.execute("""
                    SELECT 
                        sl.domain,
                        sl.reason as original_url,
                        sl.user_id,
                        CASE 
                            WHEN sl.reason LIKE '%Severity: %' THEN 
                                SUBSTRING_INDEX(SUBSTRING_INDEX(sl.reason, 'Severity: ', -1), '/', 1)
                            ELSE 5
                        END as severity_level,
                        CASE 
                            WHEN sl.reason LIKE '%Malicious: %' THEN 
                                SUBSTRING_INDEX(SUBSTRING_INDEX(sl.reason, 'Malicious: ', -1), ')', 1)
                            ELSE 0
                        END as malicious_score,
                        sl.blocked_at as added_at,
                        u.email
                    FROM sinkhole_logs sl
                    LEFT JOIN users u ON sl.user_id = u.user_id
                    WHERE sl.reason LIKE '%AUTO-DETECTED%'
                    ORDER BY sl.blocked_at DESC 
                    LIMIT %s
                """, (limit,))
                
                results = cursor.fetchall()
            
            return results
            
        except mysql.connector.Error as err:
            print(f"Error getting auto-sinkhole log: {err}")
            return []
        finally:
            cursor.close()
            conn.close()

    def _update_sinkhole_stats(self, action_type):
        """Update sinkhole statistics"""
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            # Create stats table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sinkhole_stats (
                    id INT PRIMARY KEY DEFAULT 1,
                    total_domains INT DEFAULT 0,
                    auto_added INT DEFAULT 0,
                    manual_added INT DEFAULT 0,
                    blocked_requests INT DEFAULT 0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            
            # Insert or update stats
            if action_type == 'auto_added':
                cursor.execute("""
                    INSERT INTO sinkhole_stats (id, auto_added, total_domains) 
                    VALUES (1, 1, 1)
                    ON DUPLICATE KEY UPDATE 
                    auto_added = auto_added + 1,
                    total_domains = total_domains + 1
                """)
            elif action_type == 'manual_added':
                cursor.execute("""
                    INSERT INTO sinkhole_stats (id, manual_added, total_domains) 
                    VALUES (1, 1, 1)
                    ON DUPLICATE KEY UPDATE 
                    manual_added = manual_added + 1,
                    total_domains = total_domains + 1
                """)
            elif action_type == 'blocked_request':
                cursor.execute("""
                    INSERT INTO sinkhole_stats (id, blocked_requests) 
                    VALUES (1, 1)
                    ON DUPLICATE KEY UPDATE 
                    blocked_requests = blocked_requests + 1
                """)
            
            conn.commit()
            
        except mysql.connector.Error as err:
            print(f"Error updating sinkhole stats: {err}")
        finally:
            cursor.close()
            conn.close()

    def bulk_add_malicious_domains(self, domain_list, user_id, reason_prefix="Bulk import"):
        """Add multiple domains at once (useful for threat intel feeds)"""
        successful = 0
        failed = 0
        
        print(f"🔄 Bulk adding {len(domain_list)} domains to sinkhole...")
        
        for domain_info in domain_list:
            if isinstance(domain_info, dict):
                domain = domain_info.get('domain')
                reason = f"{reason_prefix}: {domain_info.get('reason', 'Unknown threat')}"
            else:
                domain = str(domain_info)
                reason = f"{reason_prefix}: Threat intelligence"
            
            try:
                if self.add_domain_to_sinkhole(domain, user_id, reason):
                    successful += 1
                    self._update_sinkhole_stats('manual_added')
                else:
                    failed += 1
            except Exception as e:
                print(f"Error adding {domain}: {e}")
                failed += 1
        
        print(f"✅ Bulk addition complete: {successful} successful, {failed} failed")
        return {'successful': successful, 'failed': failed}

    def get_blocked_requests_log(self, limit=100):
        """Get log of blocked requests"""
        conn = self._connect_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            cursor.execute("""
                SELECT * FROM blocked_requests 
                ORDER BY blocked_at DESC 
                LIMIT %s
            """, (limit,))
            
            return cursor.fetchall()
            
        except mysql.connector.Error as err:
            print(f"Error getting blocked requests: {err}")
            return []
        finally:
            cursor.close()
            conn.close()

    def remove_domain_from_sinkhole(self, domain, user_id, reason="Manual removal"):
        """Remove a domain from the sinkhole"""
        print(f"🔧 Removing {domain} from sinkhole...")
        
        # Clean domain name
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            base_domain = domain[4:]
        else:
            base_domain = domain
        
        conn = self._connect_db()
        cursor = conn.cursor()
        
        try:
            # Check if domain exists
            cursor.execute("SELECT id FROM sinkhole_logs WHERE domain = %s", (base_domain,))
            existing = cursor.fetchone()
            
            if not existing:
                print(f"❌ {base_domain} not found in sinkhole database")
                return False
            
            # Remove from database
            cursor.execute("DELETE FROM sinkhole_logs WHERE domain = %s", (base_domain,))
            conn.commit()
            print(f"✅ Removed {base_domain} from database")
            
            # Remove from hosts file (this will remove all variants)
            hosts_success = self._remove_from_hosts_file(base_domain)
            
            # Flush DNS cache
            flush_success = self._force_dns_flush()
            
            # Verify removal
            print(f"\n🧪 Verifying removal of {base_domain}...")
            
            # Test DNS resolution
            try:
                resolved_ip = socket.gethostbyname(base_domain)
                if resolved_ip == self.sinkhole_ip:
                    print(f"⚠️ DNS still resolves to sinkhole: {base_domain} → {resolved_ip}")
                    print(f"💡 Try clearing browser cache or waiting for DNS propagation")
                else:
                    print(f"✅ DNS now resolves normally: {base_domain} → {resolved_ip}")
            except Exception as e:
                print(f"⚠️ DNS resolution test failed: {e}")
            
            # Check if still in hosts file
            try:
                with open('/etc/hosts', 'r') as f:
                    hosts_content = f.read()
                    if base_domain in hosts_content:
                        print(f"⚠️ Domain still found in hosts file - manual cleanup may be needed")
                    else:
                        print(f"✅ Domain completely removed from hosts file")
            except:
                pass
            
            print(f"\n✅ {base_domain} removal completed!")
            print(f"📋 Important: You may need to:")
            print(f"   1. Restart your browser")
            print(f"   2. Clear browser cache (Ctrl+Shift+Delete)")
            print(f"   3. Wait 30-60 seconds for DNS propagation")
            print(f"   4. Try accessing in Incognito/Private mode")
            
            return True
            
        except mysql.connector.Error as err:
            print(f"❌ Database error removing {base_domain}: {err}")
            return False
        finally:
            cursor.close()
            conn.close()

    def _remove_from_hosts_file(self, domain):
        """Remove domain and all its variants from hosts file"""
        hosts_path = '/etc/hosts'
        
        # Create list of all possible domain variants to remove
        domain_variants = [
            domain,
            f"www.{domain}",
            f"m.{domain}",
            f"mobile.{domain}"
        ]
        
        # Remove duplicates
        domain_variants = list(set(domain_variants))
        
        try:
            # Try direct file access first
            with open(hosts_path, 'r') as f:
                lines = f.readlines()
            
            # Filter out all sinkhole entries for this domain
            filtered_lines = []
            removed_count = 0
            
            for line in lines:
                should_keep = True
                
                # Check if this line contains any of our domain variants
                for variant in domain_variants:
                    if (f"{self.sinkhole_ip} {variant}" in line and "DNS Sinkhole" in line):
                        should_keep = False
                        removed_count += 1
                        print(f"🗑️ Removing: {variant}")
                        break
                
                if should_keep:
                    filtered_lines.append(line)
            
            # Write back filtered content
            with open(hosts_path, 'w') as f:
                f.writelines(filtered_lines)
                
            if removed_count > 0:
                print(f"✅ Removed {removed_count} entries for {domain} from hosts file")
            else:
                print(f"⚠️ No entries found for {domain} in hosts file")
            
            return True
            
        except PermissionError:
            print(f"❌ Permission denied. Attempting sudo method...")
            return self._remove_from_hosts_with_sudo(domain_variants)
        except Exception as e:
            print(f"❌ Error removing from hosts file: {e}")
            return False

    def _remove_from_hosts_with_sudo(self, domain_variants):
        """Remove entries from hosts file using sudo"""
        hosts_path = '/etc/hosts'
        
        try:
            # Create backup first
            backup_cmd = ['sudo', 'cp', hosts_path, f'{hosts_path}.backup']
            subprocess.run(backup_cmd, capture_output=True, text=True, timeout=10)
            
            # Use sed to remove lines containing our sinkhole entries
            removed_count = 0
            for variant in domain_variants:
                # Create pattern to match lines containing this domain variant with sinkhole IP
                pattern = f"/{self.sinkhole_ip} {variant}/d"
                cmd = ['sudo', 'sed', '-i', '', pattern, hosts_path]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        print(f"✅ Removed {variant} using sudo")
                        removed_count += 1
                    else:
                        print(f"⚠️ Failed to remove {variant}: {result.stderr}")
                except Exception as e:
                    print(f"⚠️ Error removing {variant}: {e}")
                    continue
            
            if removed_count > 0:
                print(f"✅ Successfully removed {removed_count} entries using sudo")
                return True
            else:
                print(f"⚠️ No entries were removed")
                return False
                
        except Exception as e:
            print(f"❌ Sudo removal method failed: {e}")
            print(f"🔧 Manual fix required:")
            print(f"   Run these commands in terminal:")
            for variant in domain_variants:
                print(f"   sudo sed -i '' '/{self.sinkhole_ip} {variant}/d' {hosts_path}")
            print(f"   sudo dscacheutil -flushcache")
            print(f"   sudo killall -HUP mDNSResponder")
            return False

    def get_sinkhole_status(self):
        """Get overall sinkhole system status"""
        status = {
            'active_servers': len(self.blocked_servers),
            'server_ports': list(self.blocked_servers.keys()),
            'total_domains': 0,
            'system_healthy': True,
            'dns_working': True
        }
        
        # Get domain count
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sinkhole_logs")
            result = cursor.fetchone()
            status['total_domains'] = result[0] if result else 0
            cursor.close()
            conn.close()
        except:
            status['system_healthy'] = False
        
        # Test DNS functionality with a known domain
        test_domains = ['secure.eicar.org', 'test-malware.com']
        for domain in test_domains:
            if self._is_domain_sinkholed(domain):
                try:
                    resolved_ip = socket.gethostbyname(domain)
                    if resolved_ip != self.sinkhole_ip:
                        status['dns_working'] = False
                        break
                except:
                    pass
        
        status['overall_status'] = (
            status['system_healthy'] and 
            status['active_servers'] > 0 and 
            status['dns_working']
        )
        
        return status