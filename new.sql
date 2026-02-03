-- Complete Database Schema for Cybersecurity Application
-- This file includes all tables used by the backend code

-- Check if database exists and use it, otherwise create it
DROP DATABASE IF EXISTS cybersecurity_db;
CREATE DATABASE cybersecurity_db;

-- Use the database
USE cybersecurity_db;

-- Drop tables if they exist (in the correct order to avoid foreign key constraints)
DROP TABLE IF EXISTS auto_sinkhole_log;
DROP TABLE IF EXISTS blocked_requests;
DROP TABLE IF EXISTS sinkhole_stats;
DROP TABLE IF EXISTS threat_analysis_submissions;
DROP TABLE IF EXISTS incident_reports;
DROP TABLE IF EXISTS threat_indicator;
DROP TABLE IF EXISTS sinkhole_logs;
DROP TABLE IF EXISTS url_analysis_results;
DROP TABLE IF EXISTS threat_intel_indicators;
DROP TABLE IF EXISTS threat_intel_feeds;
DROP TABLE IF EXISTS users;

-- Create the users table with a CHECK constraint on the role column
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('Admin', 'Reviewer')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

-- Create the threat_indicator table
CREATE TABLE IF NOT EXISTS threat_indicator (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    website_url VARCHAR(255),
    malicious_detections INT,
    suspicious_detections INT,
    harmless_detections INT,
    severity_level FLOAT,
    scan_date DATETIME,
    api_source VARCHAR(100),
    scan_details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_scan_date (scan_date),
    INDEX idx_severity (severity_level)
);

-- Create the incident_reports table
CREATE TABLE IF NOT EXISTS incident_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    malicious_url VARCHAR(255) NOT NULL,
    severity_level INT NOT NULL,
    malicious_detections INT NOT NULL,
    report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolution_status VARCHAR(50) NOT NULL DEFAULT 'Open',
    description TEXT,
    mitigation_steps TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_severity (severity_level),
    INDEX idx_status (resolution_status),
    INDEX idx_report_date (report_date)
);

-- Create threat_analysis_submissions table
CREATE TABLE IF NOT EXISTS threat_analysis_submissions (
    submission_id INT AUTO_INCREMENT PRIMARY KEY,
    submitted_by INT,
    url VARCHAR(255),
    severity_level INT,
    description TEXT,
    analysis_result TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'Pending',
    FOREIGN KEY (submitted_by) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_submitted_by (submitted_by),
    INDEX idx_status (status),
    INDEX idx_submitted_at (submitted_at)
);

-- DNS Sinkhole Tables

-- Main sinkhole logs table
CREATE TABLE IF NOT EXISTS sinkhole_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    domain VARCHAR(255) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_domain (domain),
    INDEX idx_blocked_at (blocked_at),
    INDEX idx_user_id (user_id)
);

-- Auto sinkhole log table (for API-detected malicious domains)
CREATE TABLE IF NOT EXISTS auto_sinkhole_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    original_url TEXT,
    user_id INT,
    severity_level INT,
    malicious_score INT,
    suspicious_score INT,
    harmless_score INT,
    detection_source VARCHAR(100) DEFAULT 'API_SCAN',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_domain (domain),
    INDEX idx_added_at (added_at),
    INDEX idx_severity (severity_level)
);

-- Blocked requests log table
CREATE TABLE IF NOT EXISTS blocked_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    client_ip VARCHAR(45),
    request_path TEXT,
    request_method VARCHAR(10),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    referrer TEXT,
    INDEX idx_domain (domain),
    INDEX idx_client_ip (client_ip),
    INDEX idx_blocked_at (blocked_at)
);

-- Sinkhole statistics table
CREATE TABLE IF NOT EXISTS sinkhole_stats (
    id INT PRIMARY KEY DEFAULT 1,
    total_domains INT DEFAULT 0,
    auto_added INT DEFAULT 0,
    manual_added INT DEFAULT 0,
    blocked_requests INT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- URL Analysis Tables

-- URL Analysis results table
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
    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_original_url (original_url),
    INDEX idx_analysis_date (analysis_date),
    INDEX idx_user_id (user_id)
);

-- Threat Intelligence Tables

-- Threat intelligence indicators table
CREATE TABLE IF NOT EXISTS threat_intel_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_type ENUM('ip', 'url', 'domain', 'hash', 'email') NOT NULL,
    indicator_value VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100),
    confidence FLOAT,
    source VARCHAR(100),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    metadata TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE KEY unique_indicator (indicator_type, indicator_value),
    INDEX idx_indicator_type (indicator_type),
    INDEX idx_indicator_value (indicator_value),
    INDEX idx_threat_type (threat_type),
    INDEX idx_confidence (confidence),
    INDEX idx_last_seen (last_seen)
);

-- Threat intelligence feeds table
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    feed_name VARCHAR(100) NOT NULL,
    feed_url VARCHAR(255) NOT NULL,
    feed_type VARCHAR(50),
    last_update TIMESTAMP,
    update_interval INT DEFAULT 86400,
    api_key VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    records_count INT DEFAULT 0,
    last_error TEXT,
    UNIQUE KEY unique_feed_name (feed_name),
    INDEX idx_enabled (enabled),
    INDEX idx_last_update (last_update)
);

-- Initialize sinkhole stats
INSERT INTO sinkhole_stats (id, total_domains, auto_added, manual_added, blocked_requests) 
VALUES (1, 0, 0, 0, 0);

-- Insert sample users with hashed passwords
INSERT INTO users (email, password, role) VALUES
('admin@example.com', '$2b$12$KIXr8Q1L7v7p2XfOp5xs4uZosUVR4yZP.4Jroa7LkfrY1PqfzgKcO', 'Admin'), -- Password: admin123
('reviewer1@example.com', '$2b$12$eZmF/owZTcdpNDrANh/BM.m0Vc7YsD2YqMHxL8h6RgA8.nZUGM2Gy', 'Reviewer'); -- Password: reviewer123

-- Insert sample threat intelligence feeds
INSERT INTO threat_intel_feeds (feed_name, feed_url, feed_type, enabled) VALUES
('Malware Domains', 'https://malware-domains.com/api/feed', 'malware', TRUE),
('Phishing URLs', 'https://phishing-feed.example.com/api', 'phishing', TRUE),
('Malicious IPs', 'https://threat-intel.example.com/ips', 'ip_reputation', TRUE);

-- Insert some sample threat indicators
INSERT INTO threat_intel_indicators (indicator_type, indicator_value, threat_type, confidence, source) VALUES
('domain', 'secure.eicar.org', 'test_malware', 0.9, 'EICAR'),
('domain', 'eicar.org', 'test_malware', 0.9, 'EICAR'),
('domain', 'malware-distribution.example.com', 'malware', 1.0, 'manual'),
('domain', 'phishing-test.example.com', 'phishing', 1.0, 'manual'),
('ip', '192.168.1.100', 'suspicious', 0.7, 'honeynet'),
('url', 'http://malware-test.com/payload.exe', 'malware', 0.95, 'url_scanner');

-- Create views for easier data access

-- View for active sinkhole domains
CREATE VIEW active_sinkhole_domains AS
SELECT 
    sl.domain,
    sl.blocked_at,
    sl.reason,
    u.email as added_by,
    CASE 
        WHEN sl.reason LIKE '%AUTO-DETECTED%' THEN 'Auto'
        ELSE 'Manual'
    END as addition_type
FROM sinkhole_logs sl
LEFT JOIN users u ON sl.user_id = u.user_id
WHERE sl.is_active = TRUE
ORDER BY sl.blocked_at DESC;

-- View for recent security events
CREATE VIEW recent_security_events AS
SELECT 
    'Threat Scan' as event_type,
    ti.website_url as target,
    ti.severity_level as severity,
    ti.scan_date as event_time,
    u.email as user_email
FROM threat_indicator ti
JOIN users u ON ti.user_id = u.user_id
WHERE ti.scan_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)

UNION ALL

SELECT 
    'Domain Blocked' as event_type,
    sl.domain as target,
    CASE 
        WHEN sl.reason LIKE '%Severity: 10%' THEN 10
        WHEN sl.reason LIKE '%Severity: 9%' THEN 9
        WHEN sl.reason LIKE '%Severity: 8%' THEN 8
        ELSE 5
    END as severity,
    sl.blocked_at as event_time,
    u.email as user_email
FROM sinkhole_logs sl
LEFT JOIN users u ON sl.user_id = u.user_id
WHERE sl.blocked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)

ORDER BY event_time DESC;

-- Create indexes for better performance
CREATE INDEX idx_threat_indicator_composite ON threat_indicator(user_id, scan_date, severity_level);
CREATE INDEX idx_sinkhole_logs_composite ON sinkhole_logs(domain, blocked_at, is_active);
CREATE INDEX idx_blocked_requests_composite ON blocked_requests(domain, blocked_at);

COMMIT;

-- Display table creation summary
SELECT 'Database schema created successfully!' as Status;
SELECT TABLE_NAME, TABLE_ROWS 
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'cybersecurity_db' 
ORDER BY TABLE_NAME;