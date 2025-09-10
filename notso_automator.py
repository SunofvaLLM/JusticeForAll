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
                'total_tools_run': len([r for r in results if r['success']]),
                'total_errors': len([r for r in results if not r['success']]),
                'total_time': str(timestamp - datetime.now())
            }
        }
        
        report_file = self.output_dir / f"comprehensive_report_{email.replace('@', '_at_')}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"Report generated at: {report_file}")
    
    def run_full_investigation(self, email):
        """Run full investigation, combining all steps"""
        results = []
        
        # Primary investigation
        primary_result = self.run_primary_investigation(email)
        results.append(primary_result)
        
        if not primary_result.get('success', False):
            print("Investigation failed at the primary forensics step.")
            return False
        
        # Identity verification
        identity_result = self.run_identity_verification(primary_result.get('evidence_file'))
        results.append(identity_result)
        
        if not identity_result.get('success', False):
            print("Investigation failed during identity verification.")
            return False
        
        # Run JSON analysis
        analysis_result = self.run_analysis(primary_result.get('evidence_file'))
        results.append(analysis_result)
        
        if not analysis_result.get('success', False):
            print("Investigation failed during analysis.")
            return False
        
        # Timeline investigation
        timeline_result = self.run_timeline_investigation(primary_result.get('evidence_file'))
        results.append(timeline_result)
        
        if not timeline_result.get('success', False):
            print("Investigation failed during timeline analysis.")
            return False
        
        # Generate comprehensive report
        self.generate_comprehensive_report(email, results)
        
        print("Investigation completed successfully")
        return True


def create_sample_config():
    """Create a sample configuration file"""
    sample_config = {
        'tools': {
            'mdm_forensics': {
                'script': 'notsofast.py',
                'required': True
            },
            'json_analyzer': {
                'script': 'json_analyzer.py',
                'required': True
            },
            'timeline_investigator': {
                'script': 'timeline_investigator.py',
                'required': True
            },
            'identity_verification': {
                'script': 'identity_verification_module.py',
                'required': True
            }
        }
    }
    
    config_file = Path(__file__).parent / 'sample_config.json'
    with open(config_file, 'w') as f:
        json.dump(sample_config, f, indent=4)
    
    print(f"Sample configuration file created at: {config_file}")


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
    
    # Validate environment before starting investigation
    if not framework.validate_environment():
        sys.exit(1)

    success = framework.run_full_investigation(args.email)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
