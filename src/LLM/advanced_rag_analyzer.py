#!/usr/bin/env python3
"""
Simple RAG-based Security Log Analyzer
Original implementation without external dependencies
Uses pattern matching and basic semantic analysis
"""

import json
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdvancedRAGAnalyzer:
    """
    Security log analyzer using retrieval-augmented generation approach.
    Analyzes logs using pattern matching and threat signatures.
    """
    
    def __init__(self, knowledge_base_dir: str, llm_model: str = 'phi3:mini',
                 n_neighbors: int = 5, use_multi_query: bool = True,
                 use_reranking: bool = True):
        """
        Initialize the RAG analyzer.
        
        Args:
            knowledge_base_dir: Path to knowledge base (not used in basic version)
            llm_model: Model name (for compatibility)
            n_neighbors: Number of neighbors (for compatibility)
            use_multi_query: Enable multi-query (for compatibility)
            use_reranking: Enable reranking (for compatibility)
        """
        self.knowledge_base_dir = Path(knowledge_base_dir)
        self.llm_model = llm_model
        self.n_neighbors = n_neighbors
        self.use_multi_query = use_multi_query
        self.use_reranking = use_reranking
        
        # Statistics tracking
        self.stats = {
            'knowledge_base_size': 0,
            'cache_size': 0,
            'total_queries': 0,
            'multi_query_enabled': use_multi_query,
            'reranking_enabled': use_reranking
        }
        
        # Simple cache for recent analyses
        self.cache = {}
        
        # Load threat signatures
        self.threat_signatures = self._load_threat_signatures()
        
        logger.info("AdvancedRAGAnalyzer initialized successfully")
    
    def _load_threat_signatures(self) -> Dict[str, Dict[str, Any]]:
        """
        Load threat detection signatures and patterns.
        
        Returns:
            Dictionary of threat signatures
        """
        return {
            'brute_force': {
                'patterns': ['failed password', 'authentication failure', 
                           'failed login', 'invalid user', 'failed attempt'],
                'threat_type': 'Brute Force Attack',
                'risk_level': 'High',
                'severity': 0.8
            },
            'sql_injection': {
                'patterns': ['sql', 'union select', 'drop table', 'or 1=1', 
                           'select * from', '-- ', 'xp_cmdshell', 'exec('],
                'threat_type': 'SQL Injection',
                'risk_level': 'Critical',
                'severity': 0.95
            },
            'command_injection': {
                'patterns': ['command injection', 'shell injection', '| cat', 
                           '| nc', '; ls', '&& ', '$(', '`'],
                'threat_type': 'Command Injection',
                'risk_level': 'Critical',
                'severity': 0.95
            },
            'xss': {
                'patterns': ['<script', 'javascript:', 'onerror=', 'onload=', 
                           'onclick=', '<iframe', 'eval('],
                'threat_type': 'Cross-Site Scripting',
                'risk_level': 'High',
                'severity': 0.75
            },
            'path_traversal': {
                'patterns': ['../', '..\\', 'directory traversal', 
                           'path traversal', '/etc/passwd', 'c:\\windows'],
                'threat_type': 'Path Traversal',
                'risk_level': 'High',
                'severity': 0.8
            },
            'xxe': {
                'patterns': ['<!entity', '<!doctype', 'system "file://', 
                           'xml external entity', 'xxe'],
                'threat_type': 'XXE',
                'risk_level': 'High',
                'severity': 0.8
            },
            'ddos': {
                'patterns': ['ddos', 'denial of service', 'flood attack', 
                           'syn flood', 'udp flood', 'slowloris'],
                'threat_type': 'DDoS',
                'risk_level': 'Critical',
                'severity': 0.9
            },
            'port_scan': {
                'patterns': ['port scan', 'nmap', 'port sweep', 'reconnaissance', 
                           'network scan', 'probe'],
                'threat_type': 'Port Scanning',
                'risk_level': 'Medium',
                'severity': 0.5
            },
            'malware': {
                'patterns': ['malware', 'virus detected', 'trojan', 'ransomware', 
                           'backdoor', 'rootkit', 'worm'],
                'threat_type': 'Malware',
                'risk_level': 'Critical',
                'severity': 0.95
            },
            'exploit': {
                'patterns': ['exploit', 'cve-', 'zero-day', 'vulnerability', 
                           'remote code execution', 'rce', 'buffer overflow'],
                'threat_type': 'Exploit',
                'risk_level': 'Critical',
                'severity': 0.95
            },
            'fuzzing': {
                'patterns': ['fuzzing', 'fuzz test', 'malformed request', 
                           'invalid input', 'unexpected input'],
                'threat_type': 'Fuzzing',
                'risk_level': 'Medium',
                'severity': 0.6
            },
            'unauthorized_access': {
                'patterns': ['unauthorized', 'access denied', 'forbidden', 
                           'permission denied', '403', '401'],
                'threat_type': 'Unauthorized Access',
                'risk_level': 'High',
                'severity': 0.75
            },
            'data_exfiltration': {
                'patterns': ['data exfiltration', 'large download', 
                           'suspicious transfer', 'data leak'],
                'threat_type': 'Data Exfiltration',
                'risk_level': 'Critical',
                'severity': 0.9
            },
            'privilege_escalation': {
                'patterns': ['privilege escalation', 'sudo', 'root access', 
                           'elevated privileges', 'admin access'],
                'threat_type': 'Privilege Escalation',
                'risk_level': 'Critical',
                'severity': 0.9
            }
        }
    
    def _extract_ip_address(self, log_entry: str) -> str:
        """
        Extract IP address from log entry.
        
        Args:
            log_entry: Log entry text
            
        Returns:
            IP address or 'Unknown'
        """
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        matches = re.findall(ip_pattern, log_entry)
        return matches[0] if matches else 'Unknown'
    
    def _detect_success(self, log_entry: str) -> bool:
        """
        Check if log indicates successful/legitimate activity.
        
        Args:
            log_entry: Log entry text
            
        Returns:
            True if successful activity detected
        """
        success_indicators = [
            'successfully', 'success', 'accepted', 'authenticated',
            'logged in', 'login success', 'session opened', 'authorized'
        ]
        
        failure_indicators = [
            'failed', 'failure', 'denied', 'rejected', 'error',
            'invalid', 'incorrect', 'unauthorized'
        ]
        
        log_lower = log_entry.lower()
        
        has_success = any(indicator in log_lower for indicator in success_indicators)
        has_failure = any(indicator in log_lower for indicator in failure_indicators)
        
        return has_success and not has_failure
    
    def _match_threat_signatures(self, log_entry: str) -> List[Dict[str, Any]]:
        """
        Match log entry against threat signatures.
        
        Args:
            log_entry: Log entry text
            
        Returns:
            List of matching threat signatures
        """
        log_lower = log_entry.lower()
        matches = []
        
        for threat_id, signature in self.threat_signatures.items():
            for pattern in signature['patterns']:
                if pattern in log_lower:
                    matches.append({
                        'id': threat_id,
                        'type': signature['threat_type'],
                        'risk': signature['risk_level'],
                        'severity': signature['severity'],
                        'pattern': pattern
                    })
                    break  # Only count first match per signature
        
        return matches
    
    def _calculate_confidence(self, matches: List[Dict[str, Any]], 
                            is_success: bool) -> float:
        """
        Calculate confidence score for analysis.
        
        Args:
            matches: List of threat signature matches
            is_success: Whether log indicates success
            
        Returns:
            Confidence score (0-1)
        """
        if is_success:
            return 0.95  # High confidence for successful operations
        
        if not matches:
            return 0.7  # Default confidence for unknown patterns
        
        # Average severity of matches
        avg_severity = sum(m['severity'] for m in matches) / len(matches)
        
        # Boost confidence with multiple matches
        match_boost = min(0.1 * (len(matches) - 1), 0.2)
        
        return min(avg_severity + match_boost, 0.98)
    
    def _generate_recommendations(self, threat_type: str, 
                                 risk_level: str, 
                                 is_attack: bool) -> List[str]:
        """
        Generate security recommendations.
        
        Args:
            threat_type: Type of threat detected
            risk_level: Risk level
            is_attack: Whether it's an attack
            
        Returns:
            List of recommended actions
        """
        if not is_attack:
            return ["Continue normal monitoring"]
        
        recommendations = []
        
        # Risk-based recommendations
        if risk_level == 'Critical':
            recommendations.extend([
                "Immediately block source IP",
                "Isolate affected system",
                "Alert security team urgently",
                "Initiate incident response procedure"
            ])
        elif risk_level == 'High':
            recommendations.extend([
                "Block source IP address",
                "Alert security team",
                "Review recent activity logs",
                "Monitor for further attempts"
            ])
        elif risk_level == 'Medium':
            recommendations.extend([
                "Monitor source IP closely",
                "Enable enhanced logging",
                "Review security policies"
            ])
        else:
            recommendations.append("Log for analysis")
        
        # Threat-specific recommendations
        specific_actions = {
            'Brute Force Attack': "Implement account lockout and rate limiting",
            'SQL Injection': "Review and sanitize database queries",
            'Command Injection': "Validate and escape all user inputs",
            'Cross-Site Scripting': "Implement content security policy",
            'Path Traversal': "Restrict file system access",
            'DDoS': "Enable DDoS protection services",
            'Malware': "Run antivirus scan and malware analysis",
            'Exploit': "Apply security patches immediately",
            'Data Exfiltration': "Review data access logs and permissions",
            'Privilege Escalation': "Audit user permissions and access controls"
        }
        
        if threat_type in specific_actions:
            recommendations.append(specific_actions[threat_type])
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def analyze(self, log_entry: str) -> Optional[Dict[str, Any]]:
        """
        Analyze security log entry.
        
        Args:
            log_entry: Log entry to analyze
            
        Returns:
            Analysis results dictionary
        """
        self.stats['total_queries'] += 1
        
        try:
            # Check cache
            cache_key = hash(log_entry)
            if cache_key in self.cache:
                self.stats['cache_size'] = len(self.cache)
                return self.cache[cache_key]
            
            # Check for successful/legitimate activity
            is_success = self._detect_success(log_entry)
            
            # Match against threat signatures
            matches = self._match_threat_signatures(log_entry)
            
            # Determine if it's an attack
            is_attack = not is_success and len(matches) > 0
            
            # Determine threat type and risk level
            if is_success:
                threat_type = 'Normal'
                risk_level = 'N/A'
            elif matches:
                # Use highest severity match
                primary_match = max(matches, key=lambda x: x['severity'])
                threat_type = primary_match['type']
                risk_level = primary_match['risk']
            else:
                threat_type = 'Normal'
                risk_level = 'Low'
            
            # Calculate confidence
            confidence = self._calculate_confidence(matches, is_success)
            
            # Extract source IP
            source_ip = self._extract_ip_address(log_entry)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                threat_type, risk_level, is_attack
            )
            
            # Build analysis result
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry[:200],  # Truncate for storage
                'threat_type': threat_type,
                'risk_level': risk_level,
                'is_attack': is_attack,
                'confidence': confidence,
                'source_ip': source_ip,
                'recommended_actions': recommendations,
                'matches_found': len(matches)
            }
            
            # Cache result (limit cache size)
            if len(self.cache) < 1000:
                self.cache[cache_key] = analysis
                self.stats['cache_size'] = len(self.cache)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analyzer statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'knowledge_base_size': len(self.threat_signatures),
            'cache_size': len(self.cache),
            'total_queries': self.stats['total_queries'],
            'multi_query_enabled': self.use_multi_query,
            'reranking_enabled': self.use_reranking
        }


# Quick test
if __name__ == "__main__":
    analyzer = AdvancedRAGAnalyzer(
        knowledge_base_dir="/home/tejas/Projects/AIS/data/"
    )
    
    test_logs = [
        "User admin successfully logged in from 192.168.1.100",
        "Failed password for invalid user admin from 10.0.0.50 port 22",
        "SQL injection detected: ' OR '1'='1 from 203.0.113.42",
    ]
    
    for log in test_logs:
        result = analyzer.analyze(log)
        print(f"\nLog: {log}")
        print(f"  Threat: {result['threat_type']}")
        print(f"  Risk: {result['risk_level']}")
        print(f"  Attack: {result['is_attack']}")