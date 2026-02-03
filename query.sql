-- Check if database exists and use it, otherwise create it
DROP DATABASE IF EXISTS cybersecurity_db;
CREATE DATABASE cybersecurity_db;

-- Use the database
USE cybersecurity_db;

-- Drop tables if they exist (in the correct order to avoid foreign key constraints)
DROP TABLE IF EXISTS threat_analysis_submissions;
DROP TABLE IF EXISTS incident_reports;
DROP TABLE IF EXISTS threat_indicator;
-- Removing malware_repository table completely as requested
-- DROP TABLE IF EXISTS malware_repository;

-- Create the users table with a CHECK constraint on the role column
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('Admin', 'Reviewer'))
);

-- Create the threat_indicator table
CREATE TABLE threat_indicator (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    website_url VARCHAR(255),
    malicious_detections INT,
    suspicious_detections INT,
    harmless_detections INT,
    severity_level FLOAT,
    scan_date DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create the incident_reports table
CREATE TABLE incident_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    malicious_url VARCHAR(255) NOT NULL,
    severity_level INT NOT NULL,
    malicious_detections INT NOT NULL,
    report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolution_status VARCHAR(50) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create threat_analysis_submissions table
CREATE TABLE threat_analysis_submissions (
    submission_id INT AUTO_INCREMENT PRIMARY KEY,
    submitted_by INT,
    url VARCHAR(255),
    severity_level INT,
    description TEXT,
    analysis_result TEXT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submitted_by) REFERENCES users(user_id)
);

-- Add new tables for the enhanced security features

-- For DNS Sinkhole feature
CREATE TABLE IF NOT EXISTS sinkhole_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    domain VARCHAR(255) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- For URL Analysis feature
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
);

-- For Honeynet feature
CREATE TABLE IF NOT EXISTS honeynet_activity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    source_port INT,
    target_port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    payload BLOB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service_type VARCHAR(50),
    metadata TEXT
);

-- For Threat Intel feature
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
);

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
);

-- Insert sample users
INSERT INTO users (email, password, role)
VALUES
('admin@example.com', '$2b$12$KIXr8Q1L7v7p2XfOp5xs4uZosUVR4yZP.4Jroa7LkfrY1PqfzgKcO', 'Admin'), -- Password: admin123
('reviewer1@example.com', '$2b$12$eZmF/owZTcdpNDrANh/BM.m0Vc7YsD2YqMHxL8h6RgA8.nZUGM2Gy', 'Reviewer'); -- Password: reviewer123

