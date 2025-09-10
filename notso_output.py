#!/usr/bin/env python3
"""
JSON Analysis Module for MDM Forensics Results
Processes saved forensics data for pattern analysis and reporting
"""

import json
import sys
import argparse
from datetime import datetime
from collections import defaultdict, Counter
import re


class ForensicsAnalyzer:
    def __init__(self, json_file):
        """Load and parse forensics JSON data"""
        try:
            with open(json_file, 'r') as f:
                self.data = json.load(f)
            
            # Handle evidence package format
            if 'forensics_report' in self.data:
                self.forensics = self.data['forensics_report']
                self.metadata = self.data.get('legal_metadata', {})
            else:
                self.forensics = self.data
                self.metadata = {}
                
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            sys.exit(1)
    
    def analyze_endpoint_patterns(self):
        """Analyze patterns in discovered endpoints"""
        patterns = {
            'by_category': defaultdict(list),
            'by_status_code': defaultdict(list),
            'suspicious_responses': [],
            'enrollment_evidence': []
        }
        
        endpoints = self.forensics.get('active_endpoints', [])
        
        for endpoint in endpoints:
            category = endpoint.get('category', 'unknown')
            status = endpoint.get('status_code', 0)
            
            patterns['by_category'][category].append(endpoint)
            patterns['by_status_code'][status].append(endpoint)
            
            # Flag suspicious responses
            if status in [200, 401, 403] and 'microsoft' in category:
                patterns['suspicious_responses'].append({
                    'endpoint': endpoint['endpoint'],
                    'reason': f'Active Microsoft service responded with {status}',
                    'significance': 'May indicate unauthorized Office 365/Intune enrollment'
                })
            
            # Collect enrollment evidence
            if endpoint.get('enrollment_indicators'):
                patterns['enrollment_evidence'].append({
                    'endpoint': endpoint['endpoint'],
                    'evidence': endpoint['enrollment_indicators'],
                    'category': category
                })
        
        return patterns
    
    def generate_risk_assessment(self):
        """Generate risk assessment based on findings"""
        risk_factors = []
        risk_score = 0
        
        endpoints = self.forensics.get('active_endpoints', [])
        
        # Risk factor: Multiple active Microsoft endpoints
        ms_endpoints = [ep for ep in endpoints if 'microsoft' in ep.get('category', '')]
        if len(ms_endpoints) > 3:
            risk_factors.append({
                'factor': 'Multiple Microsoft endpoints active',
                'count': len(ms_endpoints),
                'risk_level': 'HIGH',
                'implication': 'Possible unauthorized Office 365 or Intune enrollment'
            })
            risk_score += 40
        
        # Risk factor: Apple DEP indicators
        apple_endpoints = [ep for ep in endpoints if 'apple' in ep.get('category', '')]
        if apple_endpoints:
            risk_factors.append({
                'factor': 'Apple MDM endpoints detected',
                'count': len(apple_endpoints),
                'risk_level': 'MEDIUM',
                'implication': 'Possible Apple Business Manager enrollment'
            })
            risk_score += 25
        
        # Risk factor: Confirmed organization IDs
        confirmed_orgs = self.forensics.get('perpetrator_analysis', {}).get('confirmed_organizations', [])
        if confirmed_orgs:
            risk_factors.append({
                'factor': 'Confirmed organization identifiers found',
                'count': len(confirmed_orgs),
                'risk_level': 'CRITICAL',
                'implication': 'Strong evidence of unauthorized enrollment'
            })
            risk_score += 60
        
        # Risk factor: Certificate anomalies
        cert_evidence = self.forensics.get('certificate_evidence', {})
        enterprise_indicators = cert_evidence.get('enterprise_indicators', [])
        if enterprise_indicators:
            risk_factors.append({
                'factor': 'Enterprise certificate indicators',
                'count': len(enterprise_indicators),
                'risk_level': 'MEDIUM',
                'implication': 'Domain may be enrolled in enterprise services'
            })
            risk_score += 20
        
        # Overall risk assessment
        if risk_score >= 80:
            overall_risk = 'CRITICAL'
            recommendation = 'Immediate action required - strong evidence of unauthorized enrollment'
        elif risk_score >= 50:
            overall_risk = 'HIGH'
            recommendation = 'Investigation recommended - multiple concerning indicators'
        elif risk_score >= 25:
            overall_risk = 'MEDIUM' 
            recommendation = 'Monitor situation - some suspicious activity detected'
        else:
            overall_risk = 'LOW'
            recommendation = 'No immediate concerns - normal baseline activity'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendation': recommendation
        }
    
    def identify_next_steps(self):
        """Suggest specific next steps based on findings"""
        steps = []
        
        risk_assessment = self.generate_risk_assessment()
        endpoints = self.forensics.get('active_endpoints', [])
        
        if risk_assessment['overall_risk'] in ['CRITICAL', 'HIGH']:
            steps.extend([
                {
                    'priority': 'IMMEDIATE',
                    'action': 'Document all device profiles and restrictions',
                    'details': 'Screenshot any MDM profiles, configuration profiles, or device restrictions'
                },
                {
                    'priority': 'IMMEDIATE', 
                    'action': 'Check device management settings',
                    'details': 'iOS: Settings > General > VPN & Device Management | Android: Settings > Security > Device Admin | Windows: Settings > Accounts > Access Work or School'
                },
                {
                    'priority': 'URGENT',
                    'action': 'Contact email provider',
                    'details': f'Report suspicious activity for domain: {self.forensics.get("domain")}'
                }
            ])
        
        # Microsoft-specific steps
        ms_endpoints = [ep for ep in endpoints if 'microsoft' in ep.get('category', '')]
        if ms_endpoints:
            steps.append({
                'priority': 'HIGH',
                'action': 'Check Microsoft account status',
                'details': 'Visit https://account.microsoft.com and review connected apps and services'
            })
        
        # Apple-specific steps  
        apple_endpoints = [ep for ep in endpoints if 'apple' in ep.get('category', '')]
        if apple_endpoints:
            steps.append({
                'priority': 'HIGH',
                'action': 'Check Apple ID management',
                'details': 'Visit https://appleid.apple.com and review account security and device management'
            })
        
        # Always include general monitoring
        steps.append({
            'priority': 'ONGOING',
            'action': 'Monitor for unusual device behavior',
            'details': 'Watch for unexpected app installations, policy changes, or access restrictions'
        })
        
        return sorted(steps, key=lambda x: {'IMMEDIATE': 0, 'URGENT': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'ONGOING': 5}[x['priority']])
    
    def export_summary_report(self, output_file=None):
        """Export a concise summary report"""
        patterns = self.analyze_endpoint_patterns()
        risk_assessment = self.generate_risk_assessment()
        next_steps = self.identify_next_steps()
        
        report = {
            'analysis_metadata': {
                'target_email': self.forensics.get('email'),
                'target_domain': self.forensics.get('domain'),
                'analysis_date': datetime.now().isoformat(),
                'original_scan_date': self.forensics.get('timestamp')
            },
            'executive_summary': {
                'total_active_endpoints': len(self.forensics.get('active_endpoints', [])),
                'risk_level': risk_assessment['overall_risk'],
                'risk_score': risk_assessment['risk_score'],
                'key_recommendation': risk_assessment['recommendation']
            },
            'findings': {
                'endpoint_patterns': patterns,
                'risk_assessment': risk_assessment,
                'recommended_actions': next_steps
            },
            'technical_details': {
                'discovered_subdomains': len(self.forensics.get('discovered_subdomains', [])),
                'dns_external_services': len(self.forensics.get('dns_history', {}).get('external_service_indicators', [])),
                'certificate_indicators': len(self.forensics.get('certificate_evidence', {}).get('enterprise_indicators', []))
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Summary report saved to: {output_file}")
        
        return report
    
    def print_analysis_report(self):
        """Print human-readable analysis report"""
        print(f"\n{'='*80}")
        print(f"MDM FORENSICS ANALYSIS REPORT")
        print(f"{'='*80}")
        
        print(f"Target: {self.forensics.get('email')}")
        print(f"Domain: {self.forensics.get('domain')}")
        print(f"Original Scan: {self.forensics.get('timestamp')}")
        print(f"Analysis Date: {datetime.now().isoformat()}")
        
        # Risk Assessment
        risk_assessment = self.generate_risk_assessment()
        print(f"\nRISK ASSESSMENT:")
        print(f"Overall Risk Level: {risk_assessment['overall_risk']}")
        print(f"Risk Score: {risk_assessment['risk_score']}/100")
        print(f"Recommendation: {risk_assessment['recommendation']}")
        
        if risk_assessment['risk_factors']:
            print(f"\nRisk Factors Identified:")
            for factor in risk_assessment['risk_factors']:
                print(f"  • {factor['factor']} ({factor['risk_level']})")
                print(f"    Count: {factor['count']}")
                print(f"    Implication: {factor['implication']}")
        
        # Endpoint Analysis
        patterns = self.analyze_endpoint_patterns()
        print(f"\nENDPOINT ANALYSIS:")
        print(f"Total Active Endpoints: {len(self.forensics.get('active_endpoints', []))}")
        
        if patterns['by_category']:
            print(f"\nEndpoints by Category:")
            for category, endpoints in patterns['by_category'].items():
                print(f"  {category}: {len(endpoints)} endpoints")
        
        if patterns['suspicious_responses']:
            print(f"\nSuspicious Responses:")
            for response in patterns['suspicious_responses'][:5]:  # Top 5
                print(f"  • {response['endpoint']}")
                print(f"    Reason: {response['reason']}")
                print(f"    Significance: {response['significance']}")
        
        # Next Steps
        next_steps = self.identify_next_steps()
        print(f"\nRECOMMENDED ACTIONS:")
        for step in next_steps:
            print(f"  [{step['priority']}] {step['action']}")
            print(f"    {step['details']}")
            print()
        
        print(f"{'='*80}")


def main():
    parser = argparse.ArgumentParser(description='Analyze MDM forensics JSON results')
    parser.add_argument('json_file', help='JSON file from MDM forensics scan')
    parser.add_argument('--export', help='Export summary report to JSON file')
    parser.add_argument('--quiet', action='store_true', help='Suppress detailed output')
    
    args = parser.parse_args()
    
    analyzer = ForensicsAnalyzer(args.json_file)
    
    if not args.quiet:
        analyzer.print_analysis_report()
    
    if args.export:
        analyzer.export_summary_report(args.export)
        print(f"Analysis complete. Summary exported to: {args.export}")


if __name__ == '__main__':
    main()
