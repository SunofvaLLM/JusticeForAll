#!/usr/bin/env python3
"""
Enrollment Timeline Investigation Module
Investigates enrollment dates and timing patterns from MDM forensics data
"""

import json
import sys
import argparse
import requests
import dns.resolver
import ssl
import socket
from datetime import datetime, timezone
from pathlib import Path
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TimelineInvestigator:
    def __init__(self, forensics_json):
        """Initialize with forensics data"""
        self.load_forensics_data(forensics_json)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def load_forensics_data(self, json_file):
        """Load forensics data from JSON file"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Handle evidence package format
            if 'forensics_report' in data:
                self.forensics = data['forensics_report']
            else:
                self.forensics = data
                
            self.email = self.forensics.get('email')
            self.domain = self.forensics.get('domain')
            
        except Exception as e:
            print(f"Error loading forensics data: {e}")
            sys.exit(1)
    
    def investigate_certificate_timestamps(self):
        """Investigate certificate issuance dates for timeline clues"""
        print("Investigating certificate timestamps...")
        
        cert_timeline = {
            'certificates': [],
            'timeline_indicators': [],
            'suspicious_patterns': []
        }
        
        # Get current certificate details
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber'),
                        'version': cert.get('version')
                    }
                    
                    cert_timeline['certificates'].append(cert_info)
                    
                    # Parse certificate dates for timeline analysis
                    if cert_info['not_before']:
                        try:
                            # Parse SSL certificate date format
                            cert_date = datetime.strptime(cert_info['not_before'], '%b %d %H:%M:%S %Y %Z')
                            cert_timeline['timeline_indicators'].append({
                                'event': 'SSL Certificate Issued',
                                'date': cert_date.isoformat(),
                                'source': 'SSL Certificate',
                                'significance': 'Domain SSL setup - possible service enrollment timeframe'
                            })
                        except ValueError:
                            pass
                    
        except Exception as e:
            cert_timeline['error'] = f"Certificate analysis failed: {str(e)}"
        
        return cert_timeline
    
    def investigate_dns_history_timestamps(self):
        """Investigate DNS record changes for enrollment timing"""
        print("Investigating DNS record history...")
        
        dns_timeline = {
            'current_records': {},
            'timeline_indicators': [],
            'service_indicators': []
        }
        
        # Analyze current DNS records for service enrollment clues
        record_types = ['TXT', 'MX', 'CNAME', 'SRV']
        
        for record_type in record_types:
            try:
                records = dns.resolver.resolve(self.domain, record_type)
                dns_timeline['current_records'][record_type] = []
                
                for record in records:
                    record_str = str(record).strip('"')
                    dns_timeline['current_records'][record_type].append(record_str)
                    
                    # Look for service enrollment indicators in DNS records
                    self._analyze_dns_record_for_enrollment(record_str, record_type, dns_timeline)
                    
            except Exception:
                continue
        
        return dns_timeline
    
    def _analyze_dns_record_for_enrollment(self, record_str, record_type, dns_timeline):
        """Analyze individual DNS record for enrollment indicators"""
        record_lower = record_str.lower()
        
        # Microsoft enrollment indicators
        ms_indicators = [
            'ms=', 'microsoft', 'outlook.com', 'office365.com', 
            'enterpriseenrollment', 'enterpriseregistration',
            'autodiscover', 'msoid'
        ]
        
        for indicator in ms_indicators:
            if indicator in record_lower:
                dns_timeline['service_indicators'].append({
                    'service': 'Microsoft Office 365/Intune',
                    'record_type': record_type,
                    'record_value': record_str,
                    'indicator': indicator,
                    'significance': 'DNS configured for Microsoft enterprise services'
                })
        
        # Google Workspace indicators
        google_indicators = ['google', 'googleapis.com', 'ghs.googlehosted.com', 'aspmx.l.google.com']
        
        for indicator in google_indicators:
            if indicator in record_lower:
                dns_timeline['service_indicators'].append({
                    'service': 'Google Workspace',
                    'record_type': record_type,
                    'record_value': record_str,
                    'indicator': indicator,
                    'significance': 'DNS configured for Google enterprise services'
                })
        
        # Apple enrollment indicators
        apple_indicators = ['apple-domain-verification', 'apple.com']
        
        for indicator in apple_indicators:
            if indicator in record_lower:
                dns_timeline['service_indicators'].append({
                    'service': 'Apple Business Manager',
                    'record_type': record_type,
                    'record_value': record_str,
                    'indicator': indicator,
                    'significance': 'DNS configured for Apple enterprise services'
                })
    
    def investigate_endpoint_timestamps(self):
        """Investigate response headers and content for timing clues"""
        print("Investigating endpoint response timestamps...")
        
        endpoint_timeline = {
            'response_timestamps': [],
            'server_dates': [],
            'enrollment_dates': []
        }
        
        active_endpoints = self.forensics.get('active_endpoints', [])
        
        def analyze_endpoint_timing(endpoint):
            """Analyze individual endpoint for timing information"""
            url = endpoint['endpoint']
            results = []
            
            try:
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=10, 
                    verify=False,
                    allow_redirects=True
                )
                
                # Analyze response headers for dates
                headers = response.headers
                
                # Look for date headers
                date_headers = ['Date', 'Last-Modified', 'Expires', 'X-Timestamp']
                for header in date_headers:
                    if header in headers:
                        try:
                            header_date = datetime.strptime(headers[header], '%a, %d %b %Y %H:%M:%S %Z')
                            results.append({
                                'endpoint': url,
                                'header': header,
                                'date': header_date.isoformat(),
                                'significance': f'Server {header.lower()} timestamp'
                            })
                        except ValueError:
                            pass
                
                # Analyze response content for enrollment dates
                content = response.text
                self._extract_enrollment_dates_from_content(url, content, results)
                
            except Exception:
                pass
            
            return results
        
        # Use threading to check endpoints efficiently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(analyze_endpoint_timing, ep) for ep in active_endpoints[:20]]  # Limit to first 20
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    endpoint_timeline['response_timestamps'].extend(results)
                except Exception:
                    continue
        
        return endpoint_timeline
    
    def _extract_enrollment_dates_from_content(self, url, content, results):
        """Extract enrollment dates from response content"""
        if not content:
            return
        
        # Look for common date patterns in responses
        date_patterns = [
            r'enrolled[:\s]*(\d{4}-\d{2}-\d{2})',
            r'enrollment[:\s]*(\d{4}-\d{2}-\d{2})',
            r'created[:\s]*(\d{4}-\d{2}-\d{2})',
            r'activated[:\s]*(\d{4}-\d{2}-\d{2})',
            r'"date"[:\s]*"([^"]+)"',
            r'"timestamp"[:\s]*"([^"]+)"',
            r'"enrollmentDate"[:\s]*"([^"]+)"'
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    # Try to parse the date
                    parsed_date = None
                    
                    # Try ISO format first
                    if 'T' in match:
                        parsed_date = datetime.fromisoformat(match.replace('Z', '+00:00'))
                    else:
                        # Try common date formats
                        for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
                            try:
                                parsed_date = datetime.strptime(match, fmt)
                                break
                            except ValueError:
                                continue
                    
                    if parsed_date:
                        results.append({
                            'endpoint': url,
                            'date': parsed_date.isoformat(),
                            'raw_value': match,
                            'pattern': pattern,
                            'significance': 'Enrollment date found in response content'
                        })
                        
                except Exception:
                    continue
    
    def investigate_organization_enrollment_history(self):
        """Investigate specific organization enrollment history"""
        print("Investigating organization enrollment history...")
        
        org_timeline = {
            'confirmed_organizations': [],
            'enrollment_evidence': [],
            'timeline_correlation': []
        }
        
        # Get confirmed organizations from forensics data
        perpetrator_analysis = self.forensics.get('perpetrator_analysis', {})
        confirmed_orgs = perpetrator_analysis.get('confirmed_organizations', [])
        
        for org in confirmed_orgs:
            org_info = {
                'organization': org.get('organization_type'),
                'evidence': org.get('evidence'),
                'confidence': org.get('confidence'),
                'source_endpoint': org.get('endpoint')
            }
            
            # Try to extract timing information from the evidence
            evidence_text = org.get('evidence', '')
            
            # Look for tenant IDs, organization IDs that we can investigate further
            if 'tenant' in evidence_text.lower():
                tenant_matches = re.findall(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', evidence_text)
                if tenant_matches:
                    org_info['tenant_id'] = tenant_matches[0]
                    # Could investigate tenant creation date via Microsoft Graph API if credentials available
            
            org_timeline['confirmed_organizations'].append(org_info)
        
        return org_timeline
    
    def correlate_timeline_events(self, cert_timeline, dns_timeline, endpoint_timeline, org_timeline):
        """Correlate timeline events to identify enrollment periods"""
        print("Correlating timeline events...")
        
        correlation = {
            'timeline_events': [],
            'enrollment_periods': [],
            'suspicious_patterns': []
        }
        
        # Collect all timestamped events
        events = []
        
        # Add certificate events
        for indicator in cert_timeline.get('timeline_indicators', []):
            events.append({
                'date': indicator['date'],
                'event': indicator['event'],
                'source': 'Certificate',
                'significance': indicator['significance']
            })
        
        # Add endpoint events
        for timestamp in endpoint_timeline.get('response_timestamps', []):
            events.append({
                'date': timestamp['date'],
                'event': f"Response timestamp from {timestamp['endpoint']}",
                'source': 'Endpoint Response',
                'significance': timestamp['significance']
            })
        
        # Sort events by date
        try:
            events.sort(key=lambda x: datetime.fromisoformat(x['date']))
        except:
            pass  # Handle any date parsing issues
        
        correlation['timeline_events'] = events
        
        # Identify potential enrollment periods (clusters of activity)
        if len(events) >= 2:
            for i in range(len(events) - 1):
                try:
                    date1 = datetime.fromisoformat(events[i]['date'])
                    date2 = datetime.fromisoformat(events[i+1]['date'])
                    
                    # If events are within 30 days of each other, consider it a period
                    if (date2 - date1).days <= 30:
                        correlation['enrollment_periods'].append({
                            'start_date': events[i]['date'],
                            'end_date': events[i+1]['date'],
                            'duration_days': (date2 - date1).days,
                            'events_in_period': [events[i], events[i+1]],
                            'significance': 'Potential enrollment activity period'
                        })
                except:
                    continue
        
        return correlation
    
    def run_timeline_investigation(self):
        """Run complete timeline investigation"""
        print(f"\nTimeline Investigation for: {self.email}")
        print(f"Domain: {self.domain}")
        print("=" * 60)
        
        timeline_results = {
            'target_email': self.email,
            'target_domain': self.domain,
            'investigation_date': datetime.now(timezone.utc).isoformat(),
            'investigation_type': 'enrollment_timeline'
        }
        
        # Phase 1: Certificate timestamp investigation
        print("\nPhase 1: Certificate Timestamps")
        cert_timeline = self.investigate_certificate_timestamps()
        timeline_results['certificate_timeline'] = cert_timeline
        
        # Phase 2: DNS history investigation
        print("\nPhase 2: DNS History Analysis")
        dns_timeline = self.investigate_dns_history_timestamps()
        timeline_results['dns_timeline'] = dns_timeline
        
        # Phase 3: Endpoint timestamp investigation
        print("\nPhase 3: Endpoint Response Analysis")
        endpoint_timeline = self.investigate_endpoint_timestamps()
        timeline_results['endpoint_timeline'] = endpoint_timeline
        
        # Phase 4: Organization enrollment history
        print("\nPhase 4: Organization Enrollment History")
        org_timeline = self.investigate_organization_enrollment_history()
        timeline_results['organization_timeline'] = org_timeline
        
        # Phase 5: Timeline correlation
        print("\nPhase 5: Timeline Correlation")
        correlation = self.correlate_timeline_events(cert_timeline, dns_timeline, endpoint_timeline, org_timeline)
        timeline_results['timeline_correlation'] = correlation
        
        return timeline_results
    
    def print_timeline_report(self, timeline_results):
        """Print human-readable timeline report"""
        print(f"\n{'='*80}")
        print(f"ENROLLMENT TIMELINE INVESTIGATION REPORT")
        print(f"{'='*80}")
        
        print(f"Target: {timeline_results['target_email']}")
        print(f"Domain: {timeline_results['target_domain']}")
        print(f"Investigation Date: {timeline_results['investigation_date']}")
        
        # Timeline Events
        correlation = timeline_results.get('timeline_correlation', {})
        events = correlation.get('timeline_events', [])
        
        if events:
            print(f"\nTIMELINE OF EVENTS:")
            print(f"-" * 50)
            for event in events:
                print(f"Date: {event['date']}")
                print(f"Event: {event['event']}")
                print(f"Source: {event['source']}")
                print(f"Significance: {event['significance']}")
                print()
        
        # Enrollment Periods
        periods = correlation.get('enrollment_periods', [])
        if periods:
            print(f"IDENTIFIED ENROLLMENT PERIODS:")
            print(f"-" * 50)
            for period in periods:
                print(f"Period: {period['start_date']} to {period['end_date']}")
                print(f"Duration: {period['duration_days']} days")
                print(f"Significance: {period['significance']}")
                print()
        
        # DNS Service Indicators
        dns_timeline = timeline_results.get('dns_timeline', {})
        service_indicators = dns_timeline.get('service_indicators', [])
        if service_indicators:
            print(f"DNS SERVICE ENROLLMENT INDICATORS:")
            print(f"-" * 50)
            for indicator in service_indicators:
                print(f"Service: {indicator['service']}")
                print(f"DNS Record: {indicator['record_type']} - {indicator['record_value']}")
                print(f"Significance: {indicator['significance']}")
                print()
        
        # Organization Timeline
        org_timeline = timeline_results.get('organization_timeline', {})
        confirmed_orgs = org_timeline.get('confirmed_organizations', [])
        if confirmed_orgs:
            print(f"ORGANIZATION ENROLLMENT EVIDENCE:")
            print(f"-" * 50)
            for org in confirmed_orgs:
                print(f"Organization: {org['organization']}")
                print(f"Evidence: {org['evidence']}")
                print(f"Confidence: {org['confidence']}")
                if 'tenant_id' in org:
                    print(f"Tenant ID: {org['tenant_id']}")
                print()


def main():
    parser = argparse.ArgumentParser(description='Investigate enrollment timeline from MDM forensics data')
    parser.add_argument('forensics_json', help='JSON file from previous MDM forensics investigation')
    parser.add_argument('--save-timeline', help='Save timeline investigation results to JSON file')
    parser.add_argument('--json-output', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    investigator = TimelineInvestigator(args.forensics_json)
    timeline_results = investigator.run_timeline_investigation()
    
    if args.json_output:
        print(json.dumps(timeline_results, indent=2))
    else:
        investigator.print_timeline_report(timeline_results)
    
    if args.save_timeline:
        with open(args.save_timeline, 'w') as f:
            json.dump(timeline_results, f, indent=2)
        print(f"\nTimeline investigation saved to: {args.save_timeline}")


if __name__ == '__main__':
    main()
