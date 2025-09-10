#!/usr/bin/env python3
"""
MDM Investigation Automation Framework
Orchestrates multiple privacy investigation tools and generates comprehensive reports
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
import time


class InvestigationFramework:
    def __init__(self, config_file=None):
        self.base_dir = Path(__file__).parent
        self.output_dir = self.base_dir / "investigation_results"
        self.output_dir.mkdir(exist_ok=True)
        
        # Default tool configurations
        self.tools = {
            'mdm_forensics': {
                'script': 'notsofast.py',
                'required': True,
                'description': 'Primary MDM endpoint enumeration and forensics'
            },
            'json_analyzer': {
                'script': 'json_analyzer.py', 
                'required': True,
                'description': 'JSON results analysis and risk assessment'
            },
            'timeline_investigator': {
                'script': 'timeline_investigator.py',
                'required': True,
                'description': 'Enrollment timeline and temporal analysis'
            },
            'identity_verification': {
                'script': 'identity_verification_module.py',
                'required': True,
                'description': 'Identity verification and OSINT investigation'
            }
        }
        
        # Load custom config if provided
        if config_file and Path(config_file).exists():
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """Load investigation configuration"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            if 'tools' in config:
                self.tools.update(config['tools'])
            
            print(f"Loaded configuration from: {config_file}")
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    def validate_environment(self):
        """Check that all required tools are available"""
        missing_tools = []
        
        for tool_name, tool_config in self.tools.items():
            script_path = self.base_dir / tool_config['script']
            
            if not script_path.exists():
                if tool_config.get('required', False):
                    missing_tools.append(f"{tool_name} ({tool_config['script']})")
                else:
                    print(f"Warning: Optional tool not found: {tool_config['script']}")
        
        if missing_tools:
            print(f"Error: Missing required tools:")
            for tool in missing_tools:
                print(f"  - {tool}")
            return False
        
        return True
    
    def run_primary_investigation(self, email, save_evidence=True):
        """Run the primary MDM forensics investigation"""
        print(f"Starting primary investigation for: {email}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_file = self.output_dir / f"forensics_{email.replace('@', '_at_')}_{timestamp}.json"
        
        # Build command
        forensics_script = self.base_dir / self.tools['mdm_forensics']['script']
        cmd = [sys.executable, str(forensics_script), email]
        
        if save_evidence:
            cmd.extend(['--save-evidence', str(evidence_file)])
        
        try:
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
            
            if result.returncode == 0:
                print("Primary investigation completed successfully")
                return {
                    'success': True,
                    'evidence_file': str(evidence_file) if save_evidence else None,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                print(f"Primary investigation failed with code: {result.returncode}")
                print(f"Error output: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
        
        except subprocess.TimeoutExpired:
            print("Primary investigation timed out after 30 minutes")
            return {'success': False, 'error': 'Investigation timed out'}
        except Exception as e:
            print(f"Error running primary investigation: {e}")
            return {'success': False, 'error': str(e)}
    
    def run_identity_verification(self, evidence_file):
        """Run identity verification and OSINT investigation"""
        if not Path(evidence_file).exists():
            print(f"Error: Evidence file not found: {evidence_file}")
            return {'success': False, 'error': 'Evidence file not found'}
        
        print(f"Running identity verification on: {evidence_file}")
        
        # Generate verification report
        verification_file = Path(evidence_file).with_suffix('.verification.json')
        
        verification_script = self.base_dir / self.tools['identity_verification']['script']
        cmd = [sys.executable, str(verification_script), evidence_file, '--save-verification', str(verification_file)]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)  # 15 min timeout
            
            if result.returncode == 0:
                print("Identity verification completed successfully")
                return {
                    'success': True,
                    'verification_file': str(verification_file),
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                print(f"Identity verification failed with code: {result.returncode}")
                print(f"Error output: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr
                }
        
        except subprocess.TimeoutExpired:
            print("Identity verification timed out after 15 minutes")
            return {'success': False, 'error': 'Identity verification timed out'}
        except Exception as e:
            print(f"Error running identity verification: {e}")
            return {'success': False, 'error': str(e)}
    
    def run_additional_tools(self, email, evidence_file):
        """Run any additional investigation tools"""
        additional_results = {}
        
        # Placeholder for additional tools like:
        # - Certificate transparency log searches
        # - OSINT gathering tools  
        # - Domain reputation checks
        # - Social media investigation
        # - Historical WHOIS analysis
        
        print("Additional tools placeholder - add custom investigation modules here")
        
        return additional_results
    
    def run_analysis(self, evidence_file):
        """Run analysis on forensics results"""
        if not Path(evidence_file).exists():
            print(f"Error: Evidence file not found: {evidence_file}")
            return {'success': False, 'error': 'Evidence file not found'}
        
        print(f"Running analysis on: {evidence_file}")
        
        # Generate analysis report
        analysis_file = Path(evidence_file).with_suffix('.analysis.json')
        
        analyzer_script = self.base_dir / self.tools['json_analyzer']['script']
        cmd = [sys.executable, str(analyzer_script), evidence_file, '--export', str(analysis_file)]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 min timeout
            
            if result.returncode == 0:
                print("Analysis completed successfully")
                return {
                    'success': True,
                    'analysis_file': str(analysis_file),
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                print(f"Analysis failed with code: {result.returncode}")
                print(f"Error output: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr
                }
        
        except subprocess.TimeoutExpired:
            print("Analysis timed out after 5 minutes")
            return {'success': False, 'error': 'Analysis timed out'}
        except Exception as e:
            print(f"Error running analysis: {e}")
            return {'success': False, 'error': str(e)}
    
    def run_timeline_investigation(self, evidence_file):
        """Run timeline investigation on forensics results"""
        if not Path(evidence_file).exists():
            print(f"Error: Evidence file not found: {evidence_file}")
            return {'success': False, 'error': 'Evidence file not found'}
        
        print(f"Running timeline investigation on: {evidence_file}")
        
        # Generate timeline report
        timeline_file = Path(evidence_file).with_suffix('.timeline.json')
        
        timeline_script = self.base_dir / self.tools['timeline_investigator']['script']
        cmd = [sys.executable, str(timeline_script), evidence_file, '--save-timeline', str(timeline_file)]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 min timeout
            
            if result.returncode == 0:
                print("Timeline investigation completed successfully")
                return {
                    'success': True,
                    'timeline_file': str(timeline_file),
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                print(f"Timeline investigation failed with code: {result.returncode}")
                print(f"Error output: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr
                }
        
        except subprocess.TimeoutExpired:
            print("Timeline investigation timed out after 10 minutes")
            return {'success': False, 'error': 'Timeline investigation timed out'}
        except Exception as e:
            print(f"Error running timeline investigation: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_comprehensive_report(self, email, results):
        """Generate a comprehensive investigation report"""
        timestamp = datetime.now()
        
        report = {
            'investigation_metadata': {
                'target_email': email,
                'investigation_date': timestamp.isoformat(),
                'framework_version': '1.0',
                'tools_used': list(self.tools.keys())
            },
            'investigation_results': results,
            'summary': {
                'total_tools_run': len([r for r in results.values() if r.get('success')]),
                'failed_tools': len([r for r in results.values() if not r.get('success')]),
                'evidence_files_generated': [r.get('evidence_file') for r in results.values() if r.get('evidence_file')],
                'analysis_files_generated': [r.get('analysis_file') for r in results.values() if r.get('analysis_file')]
            }
        }
        
        # Save comprehensive report
        report_file = self.output_dir / f"comprehensive_report_{email.replace('@', '_at_')}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nComprehensive report saved to: {report_file}")
        
        return report_file
    
    def run_full_investigation(self, email):
        """Run complete investigation workflow"""
        print(f"\n{'='*80}")
        print(f"STARTING COMPREHENSIVE MDM INVESTIGATION")
        print(f"Target: {email}")
        print(f"Time: {datetime.now()}")
        print(f"{'='*80}")
        
        if not self.validate_environment():
            print("Environment validation failed. Cannot proceed.")
            return False
        
        results = {}
        
        # Step 1: Primary forensics investigation
        print(f"\nStep 1: Primary MDM Forensics Investigation")
        print(f"-" * 50)
        primary_result = self.run_primary_investigation(email)
        results['primary_investigation'] = primary_result
        
        if not primary_result.get('success'):
            print("Primary investigation failed. Stopping workflow.")
            return False
        
        evidence_file = primary_result.get('evidence_file')
        if not evidence_file:
            print("No evidence file generated. Cannot proceed with analysis.")
            return False
        
        # Step 2: Analysis of results
        print(f"\nStep 2: Results Analysis")
        print(f"-" * 50)
        analysis_result = self.run_analysis(evidence_file)
        results['analysis'] = analysis_result
        
        # Step 3: Timeline investigation
        print(f"\nStep 3: Timeline Investigation")
        print(f"-" * 50)
        timeline_result = self.run_timeline_investigation(evidence_file)
        results['timeline_investigation'] = timeline_result
        
        # Step 4: Identity verification and OSINT
        print(f"\nStep 4: Identity Verification & OSINT Investigation")
        print(f"-" * 50)
        verification_result = self.run_identity_verification(evidence_file)
        results['identity_verification'] = verification_result
        
        # Step 5: Additional tools (if any)
        print(f"\nStep 5: Additional Investigation Tools")
        print(f"-" * 50)
        additional_results = self.run_additional_tools(email, evidence_file)
        results['additional_tools'] = additional_results
        
        # Step 6: Generate comprehensive report
        print(f"\nStep 6: Comprehensive Report Generation")Step 5: Comprehensive Report Generation")
        print(f"-" * 50)
        report_file = self.generate_comprehensive_report(email, results)
        
        print(f"\n{'='*80}")
        print(f"INVESTIGATION COMPLETE")
        print(f"{'='*80}")
        print(f"Evidence file: {evidence_file}")
        if analysis_result.get('success'):
            print(f"Analysis file: {analysis_result.get('analysis_file')}")
        if timeline_result.get('success'):
            print(f"Timeline file: {timeline_result.get('timeline_file')}")
        if verification_result.get('success'):
            print(f"Verification file: {verification_result.get('verification_file')}")
        print(f"Comprehensive report: {report_file}")
        print(f"\nAll files saved to: {self.output_dir}")
        
        return True


def create_sample_config():
    """Create a sample configuration file"""
    config = {
        "description": "MDM Investigation Framework Configuration",
        "tools": {
            "mdm_forensics": {
                "script": "notsofast.py",
                "required": True,
                "description": "Primary MDM endpoint enumeration and forensics",
                "timeout": 1800
            },
            "json_analyzer": {
                "script": "json_analyzer.py",
                "required": True, 
                "description": "JSON results analysis and risk assessment",
                "timeout": 300
            },
            "cert_transparency": {
                "script": "cert_transparency_check.py",
                "required": False,
                "description": "Certificate transparency log analysis"
            },
            "domain_reputation": {
                "script": "domain_reputation_check.py", 
                "required": False,
                "description": "Domain reputation and threat intelligence"
            }
        },
        "output_settings": {
            "save_evidence": True,
            "generate_reports": True,
            "cleanup_temp_files": False
        }
    }
    
    with open('investigation_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("Sample configuration file created: investigation_config.json")


def main():
    parser = argparse.ArgumentParser(description='MDM Investigation Automation Framework')
    parser.add_argument('email', help='Target email address to investigate')
    parser.add_argument('--config', help='Configuration file for investigation tools')
    parser.add_argument('--create-config', action='store_true', help='Create sample configuration file')
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    framework = InvestigationFramework(args.config)
    success = framework.run_full_investigation(args.email)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
