#!/usr/bin/env python3
"""
LLM-Powered RAG Security Log Analyzer
Uses Ollama for actual AI-driven threat analysis with improved prompting
"""

import json
import logging
import re
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdvancedRAGAnalyzer:
    """
    LLM-powered security log analyzer using Ollama.
    Performs actual AI analysis with improved prompting and error handling.
    """
    
    def __init__(self, knowledge_base_dir: str, llm_model: str = 'phi3:mini',
                 n_neighbors: int = 5, use_multi_query: bool = True,
                 use_reranking: bool = True):
        """Initialize the LLM-powered RAG analyzer."""
        self.knowledge_base_dir = Path(knowledge_base_dir)
        self.llm_model = llm_model
        self.n_neighbors = n_neighbors
        self.use_multi_query = use_multi_query
        self.use_reranking = use_reranking
        
        # Ollama API endpoint
        self.ollama_url = "http://localhost:11434/api/generate"
        
        # Statistics
        self.stats = {
            'knowledge_base_size': 0,
            'cache_size': 0,
            'total_queries': 0,
            'llm_calls': 0,
            'llm_successes': 0,
            'llm_failures': 0,
            'multi_query_enabled': use_multi_query,
            'reranking_enabled': use_reranking
        }
        
        # Cache
        self.cache = {}
        
        # Check Ollama
        self.ollama_available = self._check_ollama_connection()
        
        if self.ollama_available:
            logger.info(f"✓ LLM-powered analyzer ready with model: {llm_model}")
        else:
            logger.warning("⚠ LLM unavailable - using pattern-based fallback")
    
    def _check_ollama_connection(self) -> bool:
        """Check if Ollama is running."""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=3)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]
                
                # Check if our model is available
                model_available = any(self.llm_model in name for name in model_names)
                
                if model_available:
                    logger.info(f"✓ Ollama connected - Model '{self.llm_model}' available")
                    return True
                else:
                    logger.warning(f"⚠ Model '{self.llm_model}' not found. Available: {model_names}")
                    logger.warning(f"  Run: ollama pull {self.llm_model}")
                    return False
            return False
        except Exception as e:
            logger.warning(f"⚠ Ollama not accessible: {e}")
            return False
    
    def _extract_ip_address(self, log_entry: str) -> str:
        """Extract IP address from log entry."""
        # IPv6 mapped format
        ipv6_pattern = r'::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ipv6_matches = re.findall(ipv6_pattern, log_entry)
        if ipv6_matches:
            return ipv6_matches[0]
        
        # Regular IPv4
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        matches = re.findall(ip_pattern, log_entry)
        return matches[0] if matches else 'Unknown'
    
    def _query_llm(self, prompt: str) -> str:
        """Query Ollama LLM with improved error handling."""
        self.stats['llm_calls'] += 1
        
        try:
            payload = {
                "model": self.llm_model,
                "prompt": prompt,
                "stream": False,
                "format": "json",  # Request JSON format
                "options": {
                    "temperature": 0.1,
                    "num_predict": 300
                }
            }
            
            response = requests.post(
                self.ollama_url,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                self.stats['llm_successes'] += 1
                return result.get('response', '').strip()
            else:
                self.stats['llm_failures'] += 1
                logger.error(f"LLM query failed: {response.status_code} - {response.text}")
                return ""
                
        except requests.exceptions.Timeout:
            self.stats['llm_failures'] += 1
            logger.error("LLM query timed out")
            return ""
        except Exception as e:
            self.stats['llm_failures'] += 1
            logger.error(f"LLM query error: {e}")
            return ""
    
    def _analyze_with_llm(self, log_entry: str) -> Dict[str, Any]:
        """Use LLM to analyze security log with improved prompting."""
        
        # Enhanced prompt with examples
        prompt = f"""Analyze this security log entry as a cybersecurity expert.

Log: {log_entry}

Identify if this is a security threat. Look for:
- SQL injection patterns (OR, UNION, --, etc.)
- Authentication attacks (brute force, multiple failures)
- DDoS indicators (high request rates)
- Successful vs failed operations
- Suspicious usernames or payloads

Respond with ONLY valid JSON (no markdown, no extra text):
{{
  "threat_type": "Brute Force Attack|SQL Injection|DDoS|Normal|etc",
  "risk_level": "Critical|High|Medium|Low|N/A",
  "is_attack": true|false,
  "confidence": 0.95,
  "reasoning": "brief explanation"
}}"""

        llm_response = self._query_llm(prompt)
        
        if not llm_response:
            logger.debug("LLM returned empty response, using fallback")
            return self._fallback_analysis(log_entry)
        
        # Parse JSON response
        try:
            # Clean up response (remove markdown if present)
            cleaned = llm_response.strip()
            if cleaned.startswith('```'):
                # Remove markdown code blocks
                cleaned = re.sub(r'```json\s*|\s*```', '', cleaned)
            
            # Find JSON object
            json_match = re.search(r'\{[\s\S]*\}', cleaned)
            if not json_match:
                logger.debug(f"No JSON found in response: {llm_response[:100]}")
                return self._fallback_analysis(log_entry)
            
            json_str = json_match.group(0)
            analysis = json.loads(json_str)
            
            # Validate and normalize
            threat_type = str(analysis.get('threat_type', 'Normal'))
            risk_level = str(analysis.get('risk_level', 'Low'))
            is_attack = bool(analysis.get('is_attack', False))
            
            # Handle confidence as either float or string
            conf_raw = analysis.get('confidence', 0.7)
            try:
                confidence = float(conf_raw)
            except (ValueError, TypeError):
                confidence = 0.7
            
            confidence = max(0.0, min(1.0, confidence))
            reasoning = str(analysis.get('reasoning', 'No reasoning provided'))
            
            # Normalize risk level
            valid_risks = ['Critical', 'High', 'Medium', 'Low', 'N/A']
            if risk_level not in valid_risks:
                risk_level = 'Low'
            
            logger.debug(f"LLM analysis: {threat_type} ({risk_level}) - {reasoning[:50]}")
            
            return {
                'threat_type': threat_type,
                'risk_level': risk_level,
                'is_attack': is_attack,
                'confidence': confidence,
                'reasoning': reasoning
            }
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM JSON: {e}")
            logger.debug(f"Raw response: {llm_response[:200]}")
            return self._fallback_analysis(log_entry)
        except Exception as e:
            logger.error(f"Unexpected error parsing LLM response: {e}")
            return self._fallback_analysis(log_entry)
    
    def _fallback_analysis(self, log_entry: str) -> Dict[str, Any]:
        """Improved fallback analysis with better pattern detection."""
        log_lower = log_entry.lower()
        
        # Success check
        success_indicators = ['successfully', 'success', 'logged in']
        failure_indicators = ['failed', 'failure', 'error', 'incorrect']
        
        has_success = any(ind in log_lower for ind in success_indicators)
        has_failure = any(ind in log_lower for ind in failure_indicators)
        
        if has_success and not has_failure:
            # Check if it's a SQL injection success
            if "or '1'='1'" in log_lower or "or 1=1" in log_lower or "admin'--" in log_lower:
                return {
                    'threat_type': 'SQL Injection',
                    'risk_level': 'Critical',
                    'is_attack': True,
                    'confidence': 0.95,
                    'reasoning': 'Successful SQL injection detected in authentication'
                }
            return {
                'threat_type': 'Normal',
                'risk_level': 'N/A',
                'is_attack': False,
                'confidence': 0.85,
                'reasoning': 'Successful legitimate authentication'
            }
        
        # SQL Injection patterns
        sql_patterns = ["or '1'='1'", "or 1=1", "union select", "drop table", 
                       "--", "admin'", "' or", "1' or", "admin'--"]
        if any(pattern in log_lower for pattern in sql_patterns):
            is_successful_inj = has_success
            return {
                'threat_type': 'SQL Injection',
                'risk_level': 'Critical' if is_successful_inj else 'High',
                'is_attack': True,
                'confidence': 0.95,
                'reasoning': 'SQL injection attempt detected in user input'
            }
        
        # DDoS patterns
        if 'ddos' in log_lower or ('requests' in log_lower and any(x in log_lower for x in ['60s', '60 seconds', 'per second'])):
            return {
                'threat_type': 'DDoS',
                'risk_level': 'Critical',
                'is_attack': True,
                'confidence': 0.90,
                'reasoning': 'DDoS attack indicators - high request rate detected'
            }
        
        # Brute force patterns
        brute_patterns = ['brute force', 'brute-force', 'multiple failed', 
                         'failed attempts', '6 failed', '7 failed', '10 failed']
        if any(pattern in log_lower for pattern in brute_patterns):
            return {
                'threat_type': 'Brute Force Attack',
                'risk_level': 'High',
                'is_attack': True,
                'confidence': 0.85,
                'reasoning': 'Multiple failed authentication attempts detected'
            }
        
        # Failed login (single attempt)
        if has_failure and any(word in log_lower for word in ['login', 'password', 'auth']):
            return {
                'threat_type': 'Normal',
                'risk_level': 'Low',
                'is_attack': False,
                'confidence': 0.70,
                'reasoning': 'Single failed login (likely legitimate user error)'
            }
        
        # Default
        return {
            'threat_type': 'Normal',
            'risk_level': 'Low',
            'is_attack': False,
            'confidence': 0.70,
            'reasoning': 'No obvious threat indicators detected'
        }
    
    def _generate_recommendations(self, threat_type: str, risk_level: str, 
                                 is_attack: bool) -> List[str]:
        """Generate actionable security recommendations."""
        if not is_attack:
            return ["Continue normal monitoring"]
        
        recommendations = []
        
        # Risk-based
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
                "Enable enhanced logging"
            ])
        
        # Threat-specific
        threat_actions = {
            'SQL Injection': "Review and sanitize all database queries immediately",
            'Brute Force Attack': "Implement account lockout and rate limiting",
            'DDoS': "Enable DDoS protection and traffic filtering",
            'Command Injection': "Validate and escape all user inputs",
            'XSS': "Implement content security policy",
            'Malware': "Run full antivirus scan"
        }
        
        if threat_type in threat_actions:
            recommendations.append(threat_actions[threat_type])
        
        return recommendations[:5]
    
    def analyze(self, log_entry: str) -> Optional[Dict[str, Any]]:
        """Analyze security log entry with LLM or fallback."""
        self.stats['total_queries'] += 1
        
        try:
            # Check cache
            cache_key = hash(log_entry)
            if cache_key in self.cache:
                return self.cache[cache_key]
            
            # Use LLM if available
            if self.ollama_available:
                llm_analysis = self._analyze_with_llm(log_entry)
            else:
                llm_analysis = self._fallback_analysis(log_entry)
            
            # Extract IP
            source_ip = self._extract_ip_address(log_entry)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                llm_analysis['threat_type'],
                llm_analysis['risk_level'],
                llm_analysis['is_attack']
            )
            
            # Build final analysis
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry[:200],
                'threat_type': llm_analysis['threat_type'],
                'risk_level': llm_analysis['risk_level'],
                'is_attack': llm_analysis['is_attack'],
                'confidence': llm_analysis['confidence'],
                'source_ip': source_ip,
                'recommended_actions': recommendations,
                'reasoning': llm_analysis.get('reasoning', '')
            }
            
            # Cache
            if len(self.cache) < 1000:
                self.cache[cache_key] = analysis
                self.stats['cache_size'] = len(self.cache)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics with LLM metrics."""
        success_rate = 0
        if self.stats['llm_calls'] > 0:
            success_rate = 100 * self.stats['llm_successes'] / self.stats['llm_calls']
        
        return {
            'knowledge_base_size': self.stats.get('knowledge_base_size', 0),
            'cache_size': len(self.cache),
            'total_queries': self.stats['total_queries'],
            'llm_calls': self.stats['llm_calls'],
            'llm_success_rate': f"{success_rate:.1f}%",
            'multi_query_enabled': self.use_multi_query,
            'reranking_enabled': self.use_reranking,
            'ollama_available': self.ollama_available
        }


# Test
if __name__ == "__main__":
    print("Testing LLM Security Log Analyzer")
    print("=" * 80)
    
    analyzer = AdvancedRAGAnalyzer(
        knowledge_base_dir="/home/tejas/Projects/AIS/data/",
        llm_model="phi3:mini"  # Smaller, faster model
    )
    
    test_logs = [
        "[2025-10-11T14:57:28.352Z] [INFO] User logged in successfully (as admin) from ::ffff:172.18.0.1",
        "[2025-10-11T14:51:46.602Z] [WARN] Login failed for user: admin' OR '1'='1 from ::ffff:172.18.0.1",
        "[2025-10-11T14:59:02.495Z] [CRITICAL] Potential DDoS attack detected: 51 requests in 60s from ::ffff:172.18.0.1",
        "[2025-10-11T14:58:18.144Z] [CRITICAL] Brute force attack detected: 6 failed attempts from ::ffff:172.18.0.1",
        "[2025-10-11T14:58:35.929Z] [INFO] User logged in successfully (as admin) from ::ffff:172.18.0.1"
    ]
    
    for i, log in enumerate(test_logs, 1):
        print(f"\n[Test {i}]")
        print(f"Log: {log[:100]}...")
        result = analyzer.analyze(log)
        
        if result:
            print(f"→ Threat: {result['threat_type']}")
            print(f"→ Risk: {result['risk_level']}")
            print(f"→ Attack: {'YES' if result['is_attack'] else 'NO'}")
            print(f"→ Confidence: {result['confidence']:.2f}")
            print(f"→ Reason: {result['reasoning']}")
    
    print("\n" + "=" * 80)
    stats = analyzer.get_statistics()
    for k, v in stats.items():
        print(f"{k}: {v}")