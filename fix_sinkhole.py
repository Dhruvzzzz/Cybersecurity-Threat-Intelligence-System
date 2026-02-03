#!/usr/bin/env python3
"""
DNS Sinkhole Fix Script
This script helps fix DNS sinkhole issues by manually adding domains to hosts file
"""

import subprocess
import sys
import socket
from dns_sinkhole import DNSSinkhole

def check_admin_privileges():
    """Check if running with admin privileges"""
    try:
        subprocess.run(['sudo', '-n', 'true'], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def add_domains_to_hosts_manually():
    """Manually add sinkholed domains to hosts file"""
    print("🔧 DNS Sinkhole Manual Fix Tool")
    print("=" * 50)
    
    # Initialize sinkhole
    sinkhole = DNSSinkhole()
    
    # Get sinkholed domains from database
    sinkholed_domains = sinkhole.get_sinkholed_domains(100)
    
    if not sinkholed_domains:
        print("❌ No domains found in sinkhole database")
        return
    
    print(f"📋 Found {len(sinkholed_domains)} sinkholed domains")
    
    # Read current hosts file
    try:
        with open('/etc/hosts', 'r') as f:
            current_hosts = f.read()
    except PermissionError:
        print("❌ Cannot read hosts file - need admin privileges")
        return
    
    # Find domains that need to be added
    domains_to_add = []
    for domain_info in sinkholed_domains:
        domain = domain_info['domain']
        if f"127.0.0.1 {domain}" not in current_hosts:
            domains_to_add.append(domain)
            # Also add www variant
            www_domain = f"www.{domain}"
            if f"127.0.0.1 {www_domain}" not in current_hosts:
                domains_to_add.append(www_domain)
    
    if not domains_to_add:
        print("✅ All sinkholed domains are already in hosts file")
        return
    
    print(f"🔧 Need to add {len(domains_to_add)} domain entries to hosts file:")
    for domain in domains_to_add:
        print(f"   → {domain}")
    
    # Create the command to add all domains
    hosts_entries = []
    for domain in domains_to_add:
        hosts_entries.append(f"127.0.0.1 {domain}  # DNS Sinkhole")
    
    print(f"\n🚀 Adding {len(hosts_entries)} entries to hosts file...")
    
    # Method 1: Try direct sudo approach
    try:
        # Create temporary file with entries
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as tmp_file:
            for entry in hosts_entries:
                tmp_file.write(entry + '\n')
            tmp_path = tmp_file.name
        
        # Append to hosts file using sudo
        cmd = ['sudo', 'bash', '-c', f'cat {tmp_path} >> /etc/hosts']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Clean up temp file
        import os
        os.unlink(tmp_path)
        
        if result.returncode == 0:
            print("✅ Successfully added all entries to hosts file!")
            
            # Flush DNS cache
            print("🔄 Flushing DNS cache...")
            flush_commands = [
                ['sudo', 'dscacheutil', '-flushcache'],
                ['sudo', 'killall', '-HUP', 'mDNSResponder']
            ]
            
            for cmd in flush_commands:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=10)
                    print(f"✅ Executed: {' '.join(cmd)}")
                except:
                    pass
            
            print("\n🧪 Testing DNS resolution:")
            for domain in domains_to_add[:3]:  # Test first 3 domains
                try:
                    resolved_ip = socket.gethostbyname(domain)
                    if resolved_ip == "127.0.0.1":
                        print(f"✅ {domain} → {resolved_ip}")
                    else:
                        print(f"⚠️ {domain} → {resolved_ip} (expected 127.0.0.1)")
                except Exception as e:
                    print(f"❌ {domain} → Failed: {e}")
            
            print(f"\n🎉 DNS Sinkhole fix completed!")
            print(f"🌐 To test: Open browser and go to http://{domains_to_add[0]}")
            print(f"📝 You should see a red 'DOMAIN BLOCKED' page")
            print(f"💡 If still not working:")
            print(f"   1. Restart your browser completely")
            print(f"   2. Clear browser cache (Ctrl+Shift+Delete)")
            print(f"   3. Try in Incognito/Private mode")
            
        else:
            print(f"❌ Failed to add entries: {result.stderr}")
            print_manual_instructions(hosts_entries)
            
    except Exception as e:
        print(f"❌ Automatic fix failed: {e}")
        print_manual_instructions(hosts_entries)

def print_manual_instructions(hosts_entries):
    """Print manual instructions for adding hosts entries"""
    print(f"\n🔧 MANUAL FIX REQUIRED:")
    print(f"Run these commands in terminal one by one:")
    print(f"")
    for entry in hosts_entries:
        print(f"echo '{entry}' | sudo tee -a /etc/hosts")
    print(f"")
    print(f"# Then flush DNS cache:")
    print(f"sudo dscacheutil -flushcache")
    print(f"sudo killall -HUP mDNSResponder")

def main():
    print("🛡️ DNS Sinkhole Fix Tool")
    print("This tool will fix DNS blocking issues by properly configuring the hosts file")
    print("")
    
    # Check if we have the database connection
    try:
        sinkhole = DNSSinkhole()
        print("✅ Connected to sinkhole database")
    except Exception as e:
        print(f"❌ Cannot connect to database: {e}")
        return
    
    # Run the fix
    add_domains_to_hosts_manually()

if __name__ == "__main__":
    main()
