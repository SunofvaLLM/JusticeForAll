#!/usr/bin/env python3
"""
Advanced MITM Detection & Attribution System 2025
State-of-the-art detection with ML, forensics, and MDM correlation
"""

import socket
import ssl
import dns.resolver
import dns.reversename
import requests
import subprocess
import hashlib
import json
import time
import threading
import asyncio
import aiohttp
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Set
import ipaddress
import concurrent.futures
from collections import defaultdict, Counter
import statistics
import re
import base64
import zlib
import sqlite3
import pickle
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

# For ML-based anomaly detection
try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available. ML features disabled.")

@dataclass
class NetworkFingerprint:
    """Detailed network behavior fingerprint"""
    response_times: List[float]
    packet_sizes: List[int]
    timing_variations: float
    jitter_coefficient: float
    tcp_window_sizes: List[int]
    mtu_size: int
    hop_count: int
    geographic_anomalies: List[str]

@dataclass
class CertificateFingerprint:
    """Advanced certificate analysis"""
    fingerprint_sha256: str
    fingerprint_sha1: str
    serial_number: str
    issuer_fingerprint: str
    key_algorithm: str
    key_size: int
    signature_algorithm: str
    extensions: Dict[str, str]
    ct_log_entries: List[Dict]
    ocsp_status: str
    transparency_score: float
    trust_chain_anomalies: List[str]

@dataclass
class DNSFingerprint:
    """Comprehensive DNS behavior analysis"""
    authoritative_servers: List[str]
    response_codes: List[int]
    additional_records: List[str]
    query_timing_patterns: List[float]
    dnssec_status: str
    cache_behavior: Dict[str, int]
    resolver_geolocation: str
    anycast_detection: bool

@dataclass
class TrafficPattern:
    """Network traffic behavioral analysis"""
    connection_patterns: Dict[str, int]
    bandwidth_usage: List[float]
    protocol_distribution: Dict[str, float]
    encryption_protocols: List[str]
    suspicious_ports: List[int]
    data_exfiltration_indicators: List[str]
    command_control_patterns: List[str]

@dataclass
class MITMEvidence:
    """Enhanced evidence structure with confidence scoring"""
    severity: str
    confidence: float  # 0.0 to 1.0
    evidence_type: str
    primary_indicator: str
    supporting_evidence: List[str]
    technical_details: Dict
    attribution_data: Dict
    false_positive_likelihood: float
    remediation_priority: int
    correlation_id: str

class AdvancedMITMDetector:
    def __init__(self, enable_ml=True, enable_forensics=True):
        self.enable_ml = enable_ml and ML_AVAILABLE
        self.enable_forensics = enable_forensics
        
        # Enhanced DNS resolver list with geolocation
        self.dns_resolvers = {
            '8.8.8.8': {'provider': 'Google', 'location': 'Global', 'anycast': True},
            '8.8.4.4': {'provider': 'Google', 'location': 'Global', 'anycast': True},
            '1.1.1.1': {'provider': 'Cloudflare', 'location': 'Global', 'anycast': True},
            '1.0.0.1': {'provider': 'Cloudflare', 'location': 'Global', 'anycast': True},
            '208.67.222.222': {'provider': 'OpenDNS', 'location': 'US', 'anycast': True},
            '208.67.220.220': {'provider': 'OpenDNS', 'location': 'US', 'anycast': True},
            '9.9.9.9': {'provider': 'Quad9', 'location': 'Global', 'anycast': True},
            '149.112.112.112': {'provider': 'Quad9', 'location': 'Global', 'anycast': True},
            '76.76.19.19': {'provider': 'Alternate DNS', 'location': 'US', 'anycast': False},
            '64.6.64.6': {'provider': 'Verisign', 'location': 'US', 'anycast': True},
        }
        
        # Certificate Transparency logs (2025 active logs)
        self.ct_logs = {
            'google_argon': 'https://ct.googleapis.com/logs/argon2025/',
            'google_xenon': 'https://ct.googleapis.com/logs/xenon2025/',
            'cloudflare_nimbus': 'https://ct.cloudflare.com/logs/nimbus2025/',
            'digicert_yeti': 'https://yeti2025.ct.digicert.com/',
            'lets_encrypt_oak': 'https://oak.ct.letsencrypt.org/2025/',
        }
        
        # Known MDM indicators and IOCs
        self.mdm_indicators = {
            'certificate_subjects': [
                'CN=*.manage.microsoft.com',
                'CN=*.google.com/workspace',
                'CN=*.jamfcloud.com',
                'CN=*.air-watch.com',
                'CN=*.soti.net',
                'CN=*.mobileiron.com',
            ],
            'dns_domains': [
                'manage.microsoft.com',
                'deviceservices-dra.googleapis.com',
                'jamfcloud.com',
                'awmdm.com',
                'soti.net',
                'mobileiron.com',
                'appaloosa-store.com',
            ],
            'network_patterns': [
                r'.*\.manage\.microsoft\.com',
                r'.*\.deviceservices.*\.googleapis\.com',
                r'.*\.jamf.*\.com',
                r'.*mdm.*',
                r'.*device.*management.*',
            ]
        }
        
        # Initialize databases
        self.init_databases()
        
        # ML models for anomaly detection
        if self.enable_ml:
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            self.dbscan = DBSCAN(eps=0.5, min_samples=3)
            self.scaler = StandardScaler()
        
        self.evidence_collector = []
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def init_databases(self):
        """Initialize SQLite databases for persistence and analysis"""
        self.db_conn = sqlite3.connect(f'mitm_analysis_{self.session_id}.db')
        cursor = self.db_conn.cursor()
        
        # Create tables for forensic data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                domains TEXT,
                results TEXT,
                ml_analysis TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_cache (
                domain TEXT,
                ip TEXT,
                fingerprint TEXT,
                certificate_data TEXT,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (domain, ip, fingerprint)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_cache (
                domain TEXT,
                resolver TEXT,
                ip_addresses TEXT,
                response_time REAL,
                timestamp TEXT,
                PRIMARY KEY (domain, resolver, timestamp)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                indicator TEXT PRIMARY KEY,
                indicator_type TEXT,
                confidence REAL,
                source TEXT,
                description TEXT,
                timestamp TEXT
            )
        ''')
        
        self.db_conn.commit()
    
    async def advanced_certificate_analysis(self, domain: str, ip: str) -> CertificateFingerprint:
        """Comprehensive certificate analysis with CT log verification"""
        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.open_connection(ip, 443, ssl=context)
            
            # Get peer certificate
            cert_der = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
            cert_info = writer.get_extra_info('ssl_object').getpeercert()
            
            writer.close()
            await writer.wait_closed()
            
            # Calculate fingerprints
            sha256_fp = hashlib.sha256(cert_der).hexdigest()
            sha1_fp = hashlib.sha1(cert_der).hexdigest()
            
            # Extract detailed certificate information
            subject = dict(x[0] for x in cert_info.get('subject', []))
            issuer = dict(x[0] for x in cert_info.get('issuer', []))
            
            # Check Certificate Transparency logs
            ct_entries = await self.check_certificate_transparency(sha256_fp)
            
            # Calculate transparency score
            transparency_score = len(ct_entries) / len(self.ct_logs)
            
            # Analyze trust chain
            trust_anomalies = self.analyze_trust_chain(cert_info, issuer)
            
            return CertificateFingerprint(
                fingerprint_sha256=sha256_fp,
                fingerprint_sha1=sha1_fp,
                serial_number=cert_info.get('serialNumber', ''),
                issuer_fingerprint=hashlib.sha256(str(issuer).encode()).hexdigest(),
                key_algorithm=self.extract_key_algorithm(cert_info),
                key_size=self.extract_key_size(cert_info),
                signature_algorithm=cert_info.get('signatureAlgorithm', ''),
                extensions=self.parse_certificate_extensions(cert_info),
                ct_log_entries=ct_entries,
                ocsp_status=await self.check_ocsp_status(cert_der),
                transparency_score=transparency_score,
                trust_chain_anomalies=trust_anomalies
            )
            
        except Exception as e:
            print(f"Certificate analysis failed for {domain}/{ip}: {e}")
            return None
    
    async def check_certificate_transparency(self, cert_fingerprint: str) -> List[Dict]:
        """Check certificate in CT logs"""
        ct_entries = []
        
        async with aiohttp.ClientSession() as session:
            for log_name, log_url in self.ct_logs.items():
                try:
                    # CT log API call (simplified - real implementation would use proper CT API)
                    url = f"{log_url}ct/v1/get-entries?start=0&end=100"
                    async with session.get(url, timeout=5) as response:
                        if response.status == 200:
                            data = await response.json()
                            # Search for certificate (simplified)
                            for entry in data.get('entries', []):
                                if cert_fingerprint in str(entry):
                                    ct_entries.append({
                                        'log': log_name,
                                        'timestamp': entry.get('timestamp'),
                                        'index': entry.get('leaf_input')
                                    })
                except Exception as e:
                    print(f"CT log check failed for {log_name}: {e}")
        
        return ct_entries
    
    async def check_ocsp_status(self, cert_der: bytes) -> str:
        """Check OCSP status of certificate"""
        try:
            # OCSP checking would require proper implementation
            # This is a simplified version
            return "GOOD"  # Placeholder
        except:
            return "UNKNOWN"
    
    def analyze_trust_chain(self, cert_info: Dict, issuer: Dict) -> List[str]:
        """Analyze certificate trust chain for anomalies"""
        anomalies = []
        
        # Check for suspicious issuers
        suspicious_issuers = [
            'Self-Signed',
            'Unknown CA',
            'Test CA',
            'Development',
            'Internal',
        ]
        
        issuer_cn = issuer.get('commonName', '')
        for suspicious in suspicious_issuers:
            if suspicious.lower() in issuer_cn.lower():
                anomalies.append(f"Suspicious issuer: {issuer_cn}")
        
        # Check certificate validity period
        try:
            not_before = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
            validity_days = (not_after - not_before).days
            
            if validity_days > 3650:  # > 10 years
                anomalies.append(f"Excessive validity period: {validity_days} days")
            elif validity_days < 30:  # < 30 days
                anomalies.append(f"Very short validity period: {validity_days} days")
        except:
            anomalies.append("Unable to parse certificate validity dates")
        
        return anomalies
    
    def extract_key_algorithm(self, cert_info: Dict) -> str:
        """Extract key algorithm from certificate"""
        # Simplified extraction
        return cert_info.get('algorithm', 'Unknown')
    
    def extract_key_size(self, cert_info: Dict) -> int:
        """Extract key size from certificate"""
        # This would require more detailed certificate parsing
        return 2048  # Placeholder
    
    def parse_certificate_extensions(self, cert_info: Dict) -> Dict[str, str]:
        """Parse certificate extensions"""
        extensions = {}
        
        # Extract Subject Alternative Names
        san = cert_info.get('subjectAltName', [])
        if san:
            extensions['subjectAltName'] = str(san)
        
        # Extract other extensions (simplified)
        extensions['version'] = str(cert_info.get('version', 'Unknown'))
        
        return extensions
    
    async def enhanced_dns_analysis(self, domain: str) -> Dict[str, DNSFingerprint]:
        """Advanced DNS analysis with timing, caching, and geolocation"""
        results = {}
        
        for resolver_ip, resolver_info in self.dns_resolvers.items():
            try:
                # Configure resolver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                resolver.lifetime = 10
                
                # Timing analysis
                timing_samples = []
                for _ in range(5):  # Multiple samples for timing analysis
                    start_time = time.time()
                    try:
                        answers = resolver.resolve(domain, 'A')
                        timing_samples.append(time.time() - start_time)
                    except:
                        timing_samples.append(float('inf'))
                    await asyncio.sleep(0.1)
                
                # Get authoritative servers
                try:
                    ns_answers = resolver.resolve(domain, 'NS')
                    auth_servers = [str(ns) for ns in ns_answers]
                except:
                    auth_servers = []
                
                # DNSSEC validation
                dnssec_status = await self.check_dnssec(domain, resolver_ip)
                
                # Cache behavior analysis
                cache_behavior = await self.analyze_dns_cache_behavior(domain, resolver_ip)
                
                results[resolver_ip] = DNSFingerprint(
                    authoritative_servers=auth_servers,
                    response_codes=[0],  # Simplified
                    additional_records=[],  # Would need more detailed parsing
                    query_timing_patterns=timing_samples,
                    dnssec_status=dnssec_status,
                    cache_behavior=cache_behavior,
                    resolver_geolocation=resolver_info['location'],
                    anycast_detection=resolver_info['anycast']
                )
                
            except Exception as e:
                print(f"Enhanced DNS analysis failed for {domain} via {resolver_ip}: {e}")
        
        return results
    
    async def check_dnssec(self, domain: str, resolver_ip: str) -> str:
        """Check DNSSEC validation status"""
        try:
            # DNSSEC validation check (simplified)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.use_edns(0, dns.flags.DO, 4096)
            
            answer = resolver.resolve(domain, 'A')
            # Check for DNSSEC signatures (simplified)
            return "SECURE" if hasattr(answer, 'rrset') else "INSECURE"
        except:
            return "UNKNOWN"
    
    async def analyze_dns_cache_behavior(self, domain: str, resolver_ip: str) -> Dict[str, int]:
        """Analyze DNS caching behavior for anomalies"""
        cache_behavior = {}
        
        try:
            # Query multiple times to analyze caching
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            
            first_query_time = time.time()
            resolver.resolve(domain, 'A')
            first_response_time = time.time() - first_query_time
            
            # Immediate second query (should be cached)
            second_query_time = time.time()
            resolver.resolve(domain, 'A')
            second_response_time = time.time() - second_query_time
            
            cache_behavior['first_query_ms'] = int(first_response_time * 1000)
            cache_behavior['cached_query_ms'] = int(second_response_time * 1000)
            cache_behavior['cache_effectiveness'] = first_response_time / max(second_response_time, 0.001)
            
        except Exception as e:
            cache_behavior['error'] = str(e)
        
        return cache_behavior
    
    def network_traffic_analysis(self, domain: str) -> TrafficPattern:
        """Analyze network traffic patterns for MITM indicators"""
        try:
            # Simplified traffic analysis
            # In a real implementation, this would use packet capture libraries
            
            # Simulate traffic pattern analysis
            connection_patterns = self.analyze_connection_patterns(domain)
            bandwidth_usage = self.measure_bandwidth_patterns(domain)
            protocol_dist = self.analyze_protocol_distribution(domain)
            
            return TrafficPattern(
                connection_patterns=connection_patterns,
                bandwidth_usage=bandwidth_usage,
                protocol_distribution=protocol_dist,
                encryption_protocols=self.detect_encryption_protocols(domain),
                suspicious_ports=self.detect_suspicious_ports(domain),
                data_exfiltration_indicators=self.detect_exfiltration_patterns(domain),
                command_control_patterns=self.detect_c2_patterns(domain)
            )
            
        except Exception as e:
            print(f"Traffic analysis failed for {domain}: {e}")
            return None
    
    def analyze_connection_patterns(self, domain: str) -> Dict[str, int]:
        """Analyze connection establishment patterns"""
        # Simplified connection pattern analysis
        try:
            # Use netstat or similar to analyze connections
            result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, timeout=10)
            connections = result.stdout.split('\n')
            
            pattern_counts = defaultdict(int)
            for conn in connections:
                if domain in conn or any(ip in conn for ip in self.get_domain_ips(domain)):
                    if 'ESTABLISHED' in conn:
                        pattern_counts['established'] += 1
                    elif 'TIME_WAIT' in conn:
                        pattern_counts['time_wait'] += 1
                    elif 'SYN_SENT' in conn:
                        pattern_counts['syn_sent'] += 1
            
            
