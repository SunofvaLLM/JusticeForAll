#!/usr/bin/env python3
"""
Identity Verification and OSINT Investigation Module
Verifies and investigates the "who" using web scraping and OSINT methods
"""

import json
import sys
import argparse
import requests
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, quote
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IdentityVerificationInvestigator:
    def __init__(self, forensics_json):
        """Initialize with forensics data for verification"""
        self.load_forensics_data(forensics_json)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def load_forensics_data(self, json_file):
        """Load forensics data for verification"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if 'forensics_report' in data:
                self.forensics = data['forensics_report']
            else:
                self.forensics = data
                
            self.email = self.forensics.get('email')
            self.domain = self.forensics.get('domain')
            
        except Exception as e:
            print(f"Error loading forensics data: {e}")
            sys.exit(1)
    
    def verify_discovery_accuracy(self):
        """Verify the accuracy of initial discovery results"""
        print("Verifying discovery result accuracy...")
        
        verification_results = {
            'endpoint_verification': [],
            'organization_verification': [],
            'accuracy_score': 0,
            'verified_findings': [],
            'false_positives': []
        }
        
        active_endpoints = self.forensics.get('active_endpoints', [])
        
        # Re-verify active endpoints
        print(f"Re-verifying {len(active_endpoints)} active endpoints...")
        
        def verify_endpoint(endpoint_data):
            """Re-verify individual endpoint"""
            url = endpoint_data['endpoint']
            original_status = endpoint_data['status_code']
            original_method = endpoint_data['method']
            
            verification = {
                'endpoint': url,
                'original_status': original_status,
                'original_method': original_method,
                'verification_status': None,
                'verification_method': None,
                'verified': False,
                'confidence': 'UNKNOWN'
            }
            
            try:
                # Re-test with same method
                response = self.session.request(
                    original_method,
                    url,
                    timeout=15,
                    verify=False,
                    allow_redirects=True
                )
                
                verification['verification_status'] = response.status_code
                verification['verification_method'] = original_method
                
                # Check if results are consistent
                if response.status_code == original_status:
                    verification['verified'] = True
                    verification['confidence'] = 'HIGH'
                elif abs(response.status_code - original_status) <= 10:  # Similar status codes
                    verification['verified'] = True
                    verification['confidence'] = 'MEDIUM'
                else:
                    verification['verified'] = False
                    verification['confidence'] = 'LOW'
                    verification['discrepancy'] = f"Original: {original_status}, Current: {response.status_code}"
                
                # Additional verification with GET if original wasn't GET
                if original_method != 'GET':
                    try:
                        get_response = self.session.get(url, timeout=10, verify=False)
                        verification['get_verification_status'] = get_response.status_code
                        
                        # If GET also returns active response, increase confidence
                        if get_response.status_code in [200, 401, 403]:
                            verification['confidence'] = 'HIGH'
                    except:
                        pass
                        
            except Exception as e:
                verification['error'] = str(e)
                verification['verified'] = False
                verification['confidence'] = 'FAILED'
            
            return verification
        
        # Verify endpoints with threading
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(verify_endpoint, ep) for ep in active_endpoints[:50]]  # Limit verification
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    verification_results['endpoint_verification'].append(result)
                    
                    if result['verified']:
                        verification_results['verified_findings'].append(result)
                    else:
                        verification_results['false_positives'].append(result)
                        
                except Exception:
                    continue
        
        # Calculate accuracy score
        total_verified = len(verification_results['verified_findings'])
        total_tested = len(verification_results['endpoint_verification'])
        
        if total_tested > 0:
            verification_results['accuracy_score'] = (total_verified / total_tested) * 100
        
        print(f"Verification complete: {total_verified}/{total_tested} endpoints verified ({verification_results['accuracy_score']:.1f}% accuracy)")
        
        return verification_results
    
    def investigate_organization_identity(self):
        """Deep OSINT investigation of identified organizations"""
        print("Conducting deep organization identity investigation...")
        
        identity_investigation = {
            'organization_profiles': [],
            'corporate_records': [],
            'web_presence': [],
            'contact_information': [],
            'business_relationships': []
        }
        
        # Get confirmed organizations from forensics
        perpetrator_analysis = self.forensics.get('perpetrator_analysis', {})
        confirmed_orgs = perpetrator_analysis.get('confirmed_organizations', [])
        
        for org in confirmed_orgs:
            org_name = org.get('organization_type', '')
            evidence = org.get('evidence', '')
            
            # Extract specific identifiers for investigation
            org_profile = {
                'organization_name': org_name,
                'evidence_source': evidence,
                'identifiers': self._extract_organization_identifiers(evidence),
                'investigation_results': {}
            }
            
            # Investigate based on organization type
            if 'microsoft' in org_name.lower():
                org_profile['investigation_results'] = self._investigate_microsoft_organization(org_profile)
            elif 'apple' in org_name.lower():
                org_profile['investigation_results'] = self._investigate_apple_organization(org_profile)
            elif 'google' in org_name.lower():
                org_profile['investigation_results'] = self._investigate_google_organization(org_profile)
            else:
                org_profile['investigation_results'] = self._investigate_generic_organization(org_profile)
            
            identity_investigation['organization_profiles'].append(org_profile)
        
        return identity_investigation
    
    def _extract_organization_identifiers(self, evidence_text):
        """Extract specific identifiers from evidence for investigation"""
        identifiers = {}
        
        # Extract tenant IDs (Microsoft)
        tenant_matches = re.findall(
            r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
            evidence_text,
            re.IGNORECASE
        )
        if tenant_matches:
            identifiers['tenant_ids'] = tenant_matches
        
        # Extract organization names
        org_name_patterns = [
            r'organization[^"]*"([^"]+)"',
            r'company[^"]*"([^"]+)"',
            r'corp[^"]*"([^"]+)"',
            r'tenant[^"]*"([^"]+)"'
        ]
        
        for pattern in org_name_patterns:
            matches = re.findall(pattern, evidence_text, re.IGNORECASE)
            if matches:
                identifiers['organization_names'] = matches
        
        # Extract domains
        domain_matches = re.findall(
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            evidence_text
        )
        if domain_matches:
            identifiers['domains'] = list(set(domain_matches))
        
        return identifiers
    
    def _investigate_microsoft_organization(self, org_profile):
        """Investigate Microsoft-based organization"""
        investigation = {
            'tenant_information': {},
            'azure_ad_details': {},
            'office365_configuration': {},
            'public_records': []
        }
        
        identifiers = org_profile.get('identifiers', {})
        
        # Investigate tenant IDs
        if 'tenant_ids' in identifiers:
            for tenant_id in identifiers['tenant_ids']:
                tenant_info = self._investigate_microsoft_tenant(tenant_id)
                investigation['tenant_information'][tenant_id] = tenant_info
        
        # Investigate organization names
        if 'organization_names' in identifiers:
            for org_name in identifiers['organization_names']:
                public_info = self._search_organization_public_records(org_name)
                investigation['public_records'].extend(public_info)
        
        return investigation
    
    def _investigate_microsoft_tenant(self, tenant_id):
        """Investigate specific Microsoft tenant"""
        tenant_info = {
            'tenant_id': tenant_id,
            'discovery_methods': [],
            'public_information': {},
            'configuration_details': {}
        }
        
        # Try OpenID configuration discovery
        openid_urls = [
            f'https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid_configuration',
            f'https://login.microsoftonline.com/{tenant_id}/.well-known/openid_configuration'
        ]
        
        for url in openid_urls:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    config_data = response.json()
                    tenant_info['discovery_methods'].append('OpenID Configuration')
                    tenant_info['public_information']['openid_config'] = {
                        'issuer': config_data.get('issuer'),
                        'tenant_region_scope': config_data.get('tenant_region_scope'),
                        'cloud_instance_name': config_data.get('cloud_instance_name'),
                        'authorization_endpoint': config_data.get('authorization_endpoint')
                    }
                    break
            except:
                continue
        
        # Try to get tenant details via Graph API metadata
        try:
            graph_url = f'https://graph.microsoft.com/v1.0/$metadata'
            response = self.session.get(graph_url, timeout=10)
            if response.status_code == 200:
                tenant_info['discovery_methods'].append('Graph API Metadata')
        except:
            pass
        
        return tenant_info
    
    def _investigate_apple_organization(self, org_profile):
        """Investigate Apple Business Manager organization"""
        investigation = {
            'business_manager_details': {},
            'dep_configuration': {},
            'public_records': []
        }
        
        identifiers = org_profile.get('identifiers', {})
        
        # Investigate organization IDs
        if 'organization_ids' in identifiers:
            for org_id in identifiers['organization_ids']:
                investigation['business_manager_details'][org_id] = self._investigate_apple_org_id(org_id)
        
        # Search for organization names
        if 'organization_names' in identifiers:
            for org_name in identifiers['organization_names']:
                public_info = self._search_organization_public_records(org_name)
                investigation['public_records'].extend(public_info)
        
        return investigation
    
    def _investigate_apple_org_id(self, org_id):
        """Investigate specific Apple organization ID"""
        org_info = {
            'organization_id': org_id,
            'discovery_methods': [],
            'public_information': {}
        }
        
        # Try to discover Apple Business Manager configuration
        apple_urls = [
            f'https://business.apple.com/enroll/{self.domain}',
            f'https://deviceenrollment.apple.com/profile/{org_id}',
            f'https://mdmenrollment.apple.com/{org_id}'
        ]
        
        for url in apple_urls:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                if response.status_code in [200, 401, 403]:
                    org_info['discovery_methods'].append(f'Apple endpoint: {url}')
                    # Extract organization details from response
                    if response.text:
                        org_details = self._extract_apple_org_details(response.text)
                        if org_details:
                            org_info['public_information'].update(org_details)
            except:
                continue
        
        return org_info
    
    def _extract_apple_org_details(self, response_text):
        """Extract organization details from Apple responses"""
        details = {}
        
        # Look for organization name patterns
        org_patterns = [
            r'"organization"[:\s]*"([^"]+)"',
            r'"company"[:\s]*"([^"]+)"',
            r'"name"[:\s]*"([^"]+)"'
        ]
        
        for pattern in org_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                details['organization_names'] = matches
        
        return details
    
    def _investigate_google_organization(self, org_profile):
        """Investigate Google Workspace organization"""
        investigation = {
            'workspace_details': {},
            'domain_configuration': {},
            'public_records': []
        }
        
        # Investigate Google Workspace configuration
        workspace_urls = [
            f'https://accounts.google.com/.well-known/openid_configuration?domain={self.domain}',
            f'https://www.googleapis.com/admin/directory/v1/domains/{self.domain}'
        ]
        
        for url in workspace_urls:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    investigation['workspace_details']['discovery_method'] = url
                    if response.text:
                        try:
                            data = response.json()
                            investigation['workspace_details']['configuration'] = data
                        except:
                            pass
            except:
                continue
        
        return investigation
    
    def _investigate_generic_organization(self, org_profile):
        """Investigate generic organization"""
        investigation = {
            'web_presence': [],
            'corporate_records': [],
            'domain_analysis': {}
        }
        
        identifiers = org_profile.get('identifiers', {})
        
        # Search for organization names
        if 'organization_names' in identifiers:
            for org_name in identifiers['organization_names']:
                web_presence = self._search_organization_web_presence(org_name)
                investigation['web_presence'].extend(web_presence)
                
                public_records = self._search_organization_public_records(org_name)
                investigation['corporate_records'].extend(public_records)
        
        # Analyze associated domains
        if 'domains' in identifiers:
            for domain in identifiers['domains']:
                domain_analysis = self._analyze_domain_ownership(domain)
                investigation['domain_analysis'][domain] = domain_analysis
        
        return investigation
    
    def _search_organization_web_presence(self, org_name):
        """Search for organization web presence"""
        web_presence = []
        
        # Search patterns for finding organization websites
        search_patterns = [
            f'"{org_name}" site:linkedin.com',
            f'"{org_name}" "company" "corporation"',
            f'"{org_name}" "contact" "address"'
        ]
        
        # Note: In a real implementation, you'd use search APIs or web scraping
        # This is a placeholder structure
        for pattern in search_patterns:
            web_presence.append({
                'search_pattern': pattern,
                'results_found': 'placeholder - would implement actual search',
                'confidence': 'MEDIUM'
            })
        
        return web_presence
    
    def _search_organization_public_records(self, org_name):
        """Search public corporate records"""
        public_records = []
        
        # Sources for corporate record searches
        record_sources = [
            'SEC EDGAR database',
            'State corporation records',
            'Business registration databases',
            'Professional licensing boards'
        ]
        
        for source in record_sources:
            public_records.append({
                'source': source,
                'organization_name': org_name,
                'search_status': 'placeholder - would implement actual search',
                'records_found': []
            })
        
        return public_records
    
    def _analyze_domain_ownership(self, domain):
        """Analyze domain ownership information"""
        domain_analysis = {
            'domain': domain,
            'whois_information': {},
            'dns_analysis': {},
            'certificate_analysis': {}
        }
        
        # DNS analysis
        try:
            # Get various DNS records
            for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
                try:
                    records = dns.resolver.resolve(domain, record_type)
                    domain_analysis['dns_analysis'][record_type] = [str(r) for r in records]
                except:
                    continue
        except:
            pass
        
        # Note: WHOIS and certificate analysis would be implemented here
        # with appropriate libraries and API calls
        
        return domain_analysis
    
    def cross_reference_findings(self, verification_results, identity_investigation):
        """Cross-reference verification and identity findings"""
        print("Cross-referencing findings for accuracy verification...")
        
        cross_reference = {
            'verified_organizations': [],
            'confidence_ratings': {},
            'evidence_correlation': [],
            'reliability_assessment': {}
        }
        
   
