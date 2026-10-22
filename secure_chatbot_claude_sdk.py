# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║              🧪 DEVELOPMENT/TESTING CHATBOT WITH SDK INTEGRATION             ║
# ║                         WITH CLAUDE AI INTEGRATION                           ║
# ╠═══════════════════════════════════════════════════════════════════════════════╣
# ║                                                                               ║
# ║  ⚠️ DISCLAIMER: NOT an official Palo Alto Networks tool!                     ║
# ║  This is independent development code for testing API integration.           ║
# ║  Palo Alto Networks provides NO support. YOU are responsible for everything! ║
# ║                                                                               ║
# ║  🧪 TESTING PURPOSE: Demonstrates Palo Alto Networks API integration         ║
# ║     with Claude AI for development and testing purposes only                 ║
# ║                                                                               ║
# ║  WORKFLOW: User Input → Security Scan → AI Processing → Response            ║
# ║  FOR TESTING ENVIRONMENTS ONLY                                               ║
# ║                                                                               ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                        📦 IMPORT DECLARATIONS                             ║
# ║   🛡️ Security imports (requests, uuid) for Palo Alto Networks scanning   ║
# ║   🧠 AI imports (anthropic) for Claude chatbot functionality              ║
# ║   ⚙️ System imports (os, json, asyncio, time) for core operations         ║
# ╚════════════════════════════════════════════════════════════════════════════╝
import requests      # 🛡️ SECURITY: HTTP requests for Palo Alto Networks API
import json          # ⚙️ SYSTEM: JSON data processing for both security and AI
import os            # ⚙️ SYSTEM: Environment variable management
import uuid          # 🛡️ SECURITY: Unique transaction IDs for security scans
import asyncio       # ⚙️ SYSTEM: Asynchronous processing capabilities
import time          # ⚙️ SYSTEM: Performance timing for security scans
import getpass       # ⚙️ SYSTEM: Stable app_user value for scan metadata
from anthropic import Anthropic  # 🧠 AI: Official Anthropic client for Claude

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                    ⚙️ ENVIRONMENT VARIABLE LOADER                         ║
# ║  NOT SECURITY OR CHATBOT - THIS IS BASIC SYSTEM CONFIGURATION             ║
# ║                                                                            ║
# ║  WHAT THIS DOES:                                                           ║
# ║  Loads API keys and settings from a .env file if present, using           ║
# ║  python-dotenv. Real environment variables always win over .env values.   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

try:
    from dotenv import load_dotenv
    if load_dotenv():
        print("✅ Loaded environment variables from .env file")
except ImportError:
    pass  # python-dotenv is optional; export the variables yourself instead

# Claude model to use. Override with the ANTHROPIC_MODEL environment variable
# (or a line in .env) if you want a different model without editing the code.
# Model IDs retire over time; check https://docs.anthropic.com/en/docs/about-claude/models
CLAUDE_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")

# Prisma AIRS regional endpoint. US is the default; set PANW_AI_SEC_ENDPOINT to
# the EU (service-de), India (service-in), or Singapore (service-sg) host when
# your API key was issued in that region. Keys are region-specific.
PANW_AI_SEC_ENDPOINT = os.getenv(
    "PANW_AI_SEC_ENDPOINT", "https://service.api.aisecurity.paloaltonetworks.com"
).rstrip("/")

# Metadata attached to every scan. app_name and app_user show up in the Strata
# Cloud Manager session and violation views.
APP_NAME = os.getenv("PANW_AI_SEC_APP_NAME", "secure-chatbot-claude-sdk")
APP_USER = os.getenv("PANW_AI_SEC_APP_USER", getpass.getuser())

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                🛡️ PALO ALTO NETWORKS SECURITY SDK IMPORT                  ║
# ║  ⚠️  CRITICAL: THIS IS 100% SECURITY - NO CHATBOT FUNCTIONALITY HERE!     ║
# ║                                                                            ║
# ║  WHAT THIS DOES:                                                           ║
# ║  • Imports Palo Alto Networks professional-grade security scanning tools  ║
# ║  • Provides enterprise-level threat detection capabilities                 ║
# ║  • Handles authentication, scanning, and threat analysis                   ║
# ║  • Completely separate from any AI chatbot functionality                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

# Import the real Palo Alto Networks AI Security SDK
try:
    import aisecurity  # 🛡️ SECURITY: Main SDK for threat detection
    from aisecurity.generated_openapi_client import AiProfile, ScanRequestContentsInner  # 🛡️ SECURITY: Data models
    from aisecurity.exceptions import AISecSDKException  # 🛡️ SECURITY: Error handling
    SDK_AVAILABLE = True
    print("✅ Palo Alto Networks AI Security SDK imported successfully")
except ImportError as e:
    SDK_AVAILABLE = False
    print(f"❌ Failed to import Palo Alto Networks AI Security SDK: {e}")
    print("   Install with: pip install pan-aisecurity")


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║              🛡️ PALO ALTO NETWORKS SECURITY SCANNER CLASS                 ║
# ║  ⚠️  IMPORTANT: THIS ENTIRE CLASS IS PURE SECURITY - NOT CHATBOT!         ║
# ║                                                                            ║
# ║  WHAT THIS CLASS DOES FOR SECURITY:                                        ║
# ║  • Scans every user message for threats before any AI processing          ║
# ║  • Detects prompt injection, malicious URLs, toxic content, data leaks    ║
# ║  • Uses Palo Alto Networks threat intelligence APIs for testing           ║
# ║  • Implements retry logic for reliable security scanning                   ║
# ║  • Provides detailed threat analysis and recommendations                   ║
# ║                                                                            ║
# ║  THIS IS NOT THE CHATBOT - this protects the chatbot from attacks!        ║
# ╚════════════════════════════════════════════════════════════════════════════╝

class SDKSecurityScanner:
    """
    🛡️ PALO ALTO NETWORKS SDK SECURITY SCANNER - ENTERPRISE THREAT DETECTION
    
    ⚠️  CRITICAL UNDERSTANDING: This is NOT the chatbot - this PROTECTS the chatbot!
    
    SECURITY PURPOSE:
    Think of this as your personal cybersecurity team that works 24/7 to protect
    your AI chatbot from malicious attacks. It uses Palo Alto Networks' 
    professional-grade security tools to examine every message with military-level precision.

    WHAT THREATS IT STOPS:
    - 🚫 Prompt injection attacks (malicious instructions to hijack the AI)
    - 🚫 Toxic content (harassment, hate speech, inappropriate material)
    - 🚫 Malicious URLs (phishing links, malware, suspicious websites)
    - 🚫 Data leaks (attempts to extract sensitive information)
    - 🚫 AI manipulation (trying to make the chatbot behave maliciously)

    ADVANCED SECURITY CAPABILITIES:
    - 🔄 Automatic retry logic (if security check fails, tries again)
    - ⏱️ Performance monitoring (tracks scan times for optimization)
    - 📊 Detailed threat categorization (explains exactly what's wrong)
    - 🔒 Enterprise-grade reliability (used by Fortune 500 companies)
    - 🚀 Async processing (handles multiple security scans simultaneously)

    Uses the Palo Alto Networks Python SDK for secure configuration and authentication.
    """

    def __init__(self, api_key, profile_name, api_endpoint=None, num_retries=3):
        """
        🏗️ SECURITY SCANNER INITIALIZATION - PALO ALTO NETWORKS SETUP
        
        ⚠️  THIS IS 100% SECURITY CONFIGURATION - NO CHATBOT CODE HERE!
        
        WHAT HAPPENS IN THIS SECURITY SETUP:
        1. 🔐 Establishes secure connection to Palo Alto's threat detection servers
        2. ⚙️ Configures retry logic for reliable security scanning
        3. 📋 Prepares threat detection categories and security policies
        4. 🔑 Sets up API authentication with your testing credentials
        5. 🛡️ Initializes the SDK with your specific security profile
        
        Parameters (ALL SECURITY-RELATED):
        - api_key: Your Palo Alto Networks API key for authentication
        - profile_name: Your custom security profile (defines what threats to detect)
        - api_endpoint: Palo Alto's security service URL
        - num_retries: How many times to retry if security scan fails
        """
        # 🛡️ PALO ALTO NETWORKS SECURITY CONFIGURATION
        self.api_key = api_key  # 🔑 Security authentication key
        self.profile_name = profile_name  # 📋 Security policy profile
        self.api_endpoint = (api_endpoint or PANW_AI_SEC_ENDPOINT).rstrip("/")  # 🌐 Security service URL (regional)
        self.num_retries = num_retries  # 🔄 Retry policy for security reliability

        # 🏗️ INITIALIZE PALO ALTO NETWORKS SDK (SECURITY ONLY)
        aisecurity.init(
            api_key=api_key,                    # 🔑 Your security credentials
            api_endpoint=self.api_endpoint,      # 🌐 Palo Alto's security servers
            num_retries=num_retries              # 🔄 Reliability configuration
        )

        # 📊 GET SECURITY CONFIGURATION FROM SDK
        self.config = aisecurity.global_configuration  # 🛡️ Security settings and endpoints

        # 📚 THREAT CATEGORIES DICTIONARY - TRANSLATES SECURITY CODES TO HUMAN LANGUAGE
        # ⚠️  NOTE: This maps technical threat codes to user-friendly descriptions
        self.threat_categories = {
            'prompt_injection': 'Prompt Injection Attack',    # 🚫 Malicious AI instructions
            'injection': 'Prompt Injection Attack',           # 🚫 Command injection attempts  
            'agent': 'AI Agent Manipulation',                 # 🚫 AI behavior manipulation
            'url_cats': 'Malicious URL Detection',           # 🚫 Suspicious links and websites
            'dlp': 'Data Loss Prevention',                   # 🚫 Sensitive data exposure
            'toxic_content': 'Toxic Content',                # 🚫 Harmful or offensive material
            'toxicity': 'Toxic Content',                     # 🚫 Harassment and hate speech
        }

    def create_scan_request(self, prompt, response=None):
        """
        📋 SECURITY REQUEST BUILDER - PALO ALTO NETWORKS FORMAT

        ⚠️  THIS IS PURE SECURITY FUNCTIONALITY - NO CHATBOT CODE!

        SECURITY PURPOSE:
        Takes a user's message (and, on the second scan of a turn, the LLM's
        reply) and packages it into the exact format required by Palo Alto
        Networks security servers for comprehensive threat analysis.
        
        WHAT GETS SCANNED FOR SECURITY:
        • Prompt injection attempts (malicious instructions)
        • Toxic content (harassment, hate speech)
        • Malicious URLs (phishing, malware links)
        • Data leakage attempts (trying to extract sensitive info)
        • AI manipulation techniques (jailbreaking, role-playing)
        
        Returns a structured security scan request with unique transaction ID.
        """
        try:
            # 🛡️ SECURITY PROFILE CONFIGURATION
            # This tells Palo Alto which security rules to apply
            ai_profile_data = {"profile_name": self.profile_name}  # 📋 Your custom security policy
            
            # 📝 CONTENT TO BE SECURITY SCANNED
            # This packages the user's message for threat analysis. When the
            # LLM reply is supplied, it rides along so AIRS can inspect it too.
            content_data = {"prompt": prompt}  # 💬 User message to scan for threats
            if response is not None:
                content_data["response"] = response  # 📤 LLM output to scan

            # 📦 COMPLETE SECURITY SCAN REQUEST STRUCTURE
            # This creates the full request that Palo Alto's servers expect
            request_data = {
                "tr_id": str(uuid.uuid4()),        # 🆔 Unique security transaction ID
                "ai_profile": ai_profile_data,     # 📋 Security policy to apply
                "metadata": {                      # 🏢 Attribution shown in SCM sessions/violations
                    "app_name": APP_NAME,
                    "app_user": APP_USER,
                    "ai_model": CLAUDE_MODEL
                },
                "contents": [content_data]         # 💬 Content to scan for threats
            }

            return request_data  # 📤 Ready for Palo Alto security analysis

        except Exception as e:
            # 🚨 SECURITY ERROR HANDLING
            raise AISecSDKException(f"Failed to create scan request: {e}")

    def execute_scan_request(self, request_data):
        """
        🚀 SECURITY SCAN EXECUTOR - PALO ALTO NETWORKS THREAT ANALYSIS
        
        ⚠️  THIS IS PURE SECURITY SCANNING - NO CHATBOT PROCESSING HERE!
        
        SECURITY OPERATIONS:
        1. 📡 Sends user message to Palo Alto's threat detection servers
        2. 🔄 Implements testing-grade retry logic (up to 3 attempts)
        3. ⏱️ Uses exponential backoff (waits longer between retries)
        4. 🛡️ Handles authentication, network, and security policy errors
        5. 📊 Returns comprehensive threat analysis results
        
        WHAT PALO ALTO SCANS FOR:
        • Malicious instructions trying to hijack the AI
        • Toxic or harmful content that violates policies
        • Suspicious URLs that could be phishing or malware
        • Attempts to extract sensitive data or bypass security
        • Social engineering attacks targeting the AI system
        """
        # 🌐 PALO ALTO NETWORKS SECURITY API ENDPOINT
        # This is the URL where all security scans are processed
        url = f"{self.config.api_endpoint}/v1/scan/sync/request"  # 🛡️ Security scanning endpoint

        # 📋 SECURITY API HEADERS
        # These headers authenticate and identify our security requests
        headers = {
            "Content-Type": "application/json",              # 📄 Data format specification
            "Accept": "application/json",                    # 📥 Expected response format
            "x-pan-token": self.config.api_key,             # 🔑 SECURITY: Palo Alto API authentication
            "User-Agent": "PAN-AI-Security-SDK/1.0.0"       # 🏷️ SDK identification for security logs
        }

        # ╔══════════════════════════════════════════════════════════════════════╗
        # ║           🔄 ENTERPRISE SECURITY SCAN EXECUTION LOOP                 ║
        # ║  ⚠️  CRITICAL: ALL CODE BELOW IS PURE SECURITY - NO CHATBOT!        ║
        # ╚══════════════════════════════════════════════════════════════════════╝
        
        # 🔄 INTELLIGENT RETRY LOOP - ENTERPRISE-GRADE RELIABILITY
        # If security scanning fails, this automatically retries with increasing delays
        for attempt in range(self.num_retries + 1):
            try:
                # ⏱️ EXPONENTIAL BACKOFF FOR FAILED SECURITY ATTEMPTS
                if attempt > 0:
                    wait_time = 2 ** (attempt - 1)  # 📈 Wait longer each retry (1s, 2s, 4s)
                    print(f"   🔄 Security retry attempt {attempt}/{self.num_retries} (waiting {wait_time}s)")
                    time.sleep(wait_time)  # ⏰ Pause before retry

                # 📡 SEND MESSAGE TO PALO ALTO SECURITY SERVERS
                print(f"   📡 Sending security scan to Palo Alto (attempt {attempt + 1})")
                response = requests.post(
                    url,                    # 🌐 Palo Alto security endpoint
                    headers=headers,        # 🔑 Security authentication headers
                    json=request_data,      # 💬 User message packaged for scanning
                    timeout=30              # ⏰ 30-second timeout for security response
                )
                response.raise_for_status()  # 🚨 Raise exception if security API fails

                # 📊 PARSE SECURITY SCAN RESULTS
                result = response.json()  # 📄 Convert security response to data
                print(f"   ✅ Palo Alto security scan completed successfully")
                return result  # 📤 Return threat analysis results

            # ╔══════════════════════════════════════════════════════════════════════╗
            # ║                🚨 SECURITY ERROR HANDLING                          ║
            # ║  These errors are ALL related to security scanning failures        ║
            # ╚══════════════════════════════════════════════════════════════════════╝
            
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code
                # 🔑 SECURITY AUTHENTICATION ERRORS (retrying will not help)
                if status == 401:
                    raise AISecSDKException(
                        "Security authentication failed: invalid or expired Palo Alto API key")
                # 📋 BAD REQUEST: AIRS returns 400 for an unknown or misspelled
                # profile name (profile names are case-sensitive) and for
                # malformed payloads. Retrying will not help either.
                elif status == 400:
                    raise AISecSDKException(
                        f"Security scan rejected (HTTP 400): {e.response.text.strip()} "
                        f"- check PANW_AI_SEC_PROFILE_NAME ('{self.profile_name}')")
                # ⏳ RATE LIMIT or SERVER ERROR: fall through and retry with backoff
                elif attempt == self.num_retries:
                    raise AISecSDKException(
                        f"Security HTTP error {status} after {self.num_retries} retries: {e}")

            except requests.exceptions.ConnectionError as e:
                # 🌐 SECURITY NETWORK CONNECTION ERRORS
                if attempt == self.num_retries:
                    raise AISecSDKException(
                        f"Security connection failed after {self.num_retries} retries: {e}")

            except requests.exceptions.Timeout as e:
                # ⏰ SECURITY REQUEST TIMEOUT ERRORS
                if attempt == self.num_retries:
                    raise AISecSDKException(
                        f"Security request timeout after {self.num_retries} retries: {e}")

    def sync_scan(self, prompt, response=None):
        """
        🔍 SYNCHRONOUS SECURITY SCAN - COMPREHENSIVE THREAT ANALYSIS
        
        ⚠️  THIS IS THE MAIN SECURITY FUNCTION - NOT CHATBOT CODE!
        
        SECURITY PURPOSE:
        This is the core security function that analyzes every user message
        for threats BEFORE any AI processing occurs. Think of this as the
        security checkpoint that all messages must pass through.

        SECURITY ANALYSIS PERFORMED:
        1. 🕵️ Prompt injection detection (malicious AI instructions)
        2. 🚫 Toxic content analysis (harassment, hate speech)
        3. 🔗 URL threat scanning (phishing, malware links) 
        4. 🛡️ Data loss prevention (sensitive info extraction attempts)
        5. 🎭 AI manipulation detection (jailbreaking, role-playing attacks)
        6. ⏱️ Performance monitoring (scan timing for optimization)

        Args:
            prompt (str): The user's message to scan for security threats
            response (str, optional): The LLM reply to scan together with the prompt

        Returns:
            dict: Detailed security analysis with threat categories and recommendations
        """
        # ⏱️ SECURITY PERFORMANCE MONITORING
        start_time = time.time()  # 🕐 Start timing the security scan

        # 📊 SECURITY SCAN STATUS REPORTING
        what = "prompt + response" if response is not None else "prompt"
        print(f"🔍 Palo Alto Networks SDK Security Scan Starting ({what})...")
        print(f"   Content: '{prompt[:50]}...' ({len(prompt)} characters)")  # 📝 Preview of content being scanned
        print(f"   Security Profile: {self.profile_name}")                    # 📋 Which security rules are active
        print(f"   Security Endpoint: {self.config.api_endpoint}")             # 🌐 Palo Alto security server

        # 📋 CREATE SECURITY SCAN REQUEST
        # Step 1: Package the message (and optional reply) for Palo Alto analysis
        request_data = self.create_scan_request(prompt, response)  # 🛡️ SECURITY: Format content for scanning
        print(f"   Security Transaction ID: {request_data['tr_id']}")  # 🆔 Unique ID for this security check

        # 🚀 EXECUTE SECURITY SCAN
        # Step 2: Send to Palo Alto servers for comprehensive threat analysis
        scan_result = self.execute_scan_request(request_data)  # 🛡️ SECURITY: Actual threat detection

        # ⏱️ CALCULATE SECURITY SCAN PERFORMANCE
        scan_time = (time.time() - start_time) * 1000  # 📊 Convert to milliseconds
        scan_result['scan_time_ms'] = scan_time         # 📈 Add timing to results

        return scan_result  # 📤 Return complete security analysis

    async def async_scan(self, prompt, response=None):
        """
        ⚡ ASYNCHRONOUS SECURITY SCAN - HIGH-PERFORMANCE THREAT DETECTION
        
        ⚠️  THIS IS ADVANCED SECURITY SCANNING - NO CHATBOT FUNCTIONALITY!
        
        ENTERPRISE SECURITY PURPOSE:
        Runs Palo Alto Networks security scanning in a non-blocking way,
        allowing your application to handle multiple security scans simultaneously.
        Perfect for high-traffic enterprise deployments where security cannot slow down operations.

        ASYNC SECURITY BENEFITS:
        • 🚀 Multiple security scans can run in parallel
        • 📈 Higher throughput for enterprise applications
        • 🔄 Non-blocking security analysis
        • ⚡ Optimal performance for testing environments
        • 🛡️ Same comprehensive threat detection as sync version

        Args:
            prompt (str): The user's message to scan for security threats

        Returns:
            dict: Complete security analysis results (same as sync_scan)
        """
        # 🔄 ASYNC SECURITY EXECUTION
        # Runs the security scan without blocking other operations
        loop = asyncio.get_running_loop()  # ⚙️ The loop asyncio.run() created for main()
        return await loop.run_in_executor(None, self.sync_scan, prompt, response)  # 🛡️ SECURITY: Non-blocking threat scan

    def display_enhanced_results(self, scan_result):
        """
        📊 SECURITY RESULTS FORMATTER - HUMAN-READABLE THREAT REPORT
        
        ⚠️  THIS IS SECURITY REPORTING - NOT CHATBOT FUNCTIONALITY!
        
        SECURITY REPORTING PURPOSE:
        Takes raw security scan data from Palo Alto Networks and transforms it
        into a beautiful, easy-to-understand security report that shows:
        
        WHAT THE SECURITY REPORT SHOWS:
        • 🚦 Overall security classification (benign, suspicious, malicious)
        • 📋 Recommended security action (allow, warn, block)
        • 🕐 Security scan performance metrics
        • 🔍 Detailed breakdown of specific threats found
        • 💡 Security recommendations for threat remediation
        • 📊 Complete audit trail for security compliance
        
        This helps non-technical users understand what security threats
        were detected and how to fix their messages to be safe.
        """

        # ╔══════════════════════════════════════════════════════════════════════╗
        # ║              📊 SECURITY SCAN RESULTS HEADER                         ║
        # ║  Shows high-level security classification and metadata               ║
        # ╚══════════════════════════════════════════════════════════════════════╝
        
        print("\n📋 PALO ALTO NETWORKS SDK SECURITY RESULTS:")
        print("=" * 50)
        print(f"🛡️ Security Classification: {scan_result.get('category', 'Unknown')}")     # 🚦 Safe or dangerous?
        print(f"🚦 Security Action: {scan_result.get('action', 'Unknown')}")                # 🔄 Allow or block?
        print(f"📋 Security Profile: {scan_result.get('profile_name', 'Unknown')}")         # 📝 Which security rules used?
        print(f"🆔 Profile ID: {scan_result.get('profile_id', 'Unknown')}")                # 🔢 Internal security profile ID
        print(f"⏱️ Security Scan Time: {scan_result.get('scan_time_ms', 0):.1f}ms")        # 📈 Performance metrics
        print(f"🆔 Transaction ID: {scan_result.get('tr_id', 'Unknown')}")                 # 🔗 Unique security scan ID
        print(f"📄 Report ID: {scan_result.get('report_id', 'Unknown')}")                  # 📊 Security report reference
        print(f"🔍 Scan ID: {scan_result.get('scan_id', 'Unknown')}")                      # 🆔 Internal scan reference

        # ╔══════════════════════════════════════════════════════════════════════╗
        # ║              🚨 DETAILED SECURITY THREAT ANALYSIS                    ║
        # ║  This section breaks down exactly what security threats were found   ║
        # ╚══════════════════════════════════════════════════════════════════════╝
        
        print(f"\n🚨 DETAILED SECURITY THREAT ANALYSIS:")
        print("=" * 50)

        threats_found = False  # 🔍 Track if any security threats were detected

        # ╔══════════════════════════════════════════════════════════════════════════╗
        # ║                    📊 PROMPT vs RESPONSE DETECTION                       ║
        # ║                                                                          ║
        # ║  Prisma AIRS returns two detection maps:                                 ║
        # ║  • prompt_detected: detectors that fired on the user's message           ║
        # ║  • response_detected: detectors that fired on the LLM output you SENT    ║
        # ║                                                                          ║
        # ║  response_detected is only populated when the scan request includes a    ║
        # ║  "response" field. AIRS does not predict what the model will say; it     ║
        # ║  inspects what the model actually said. That is why this chatbot scans   ║
        # ║  twice per turn: prompt first, then prompt + response before display.    ║
        # ║                                                                          ║
        # ║  The two sides run different detectors. Prompt injection and agent       ║
        # ║  protection are prompt-side only; database security is response-side    ║
        # ║  only. A detector disabled in the profile is absent from the map.        ║
        # ╚══════════════════════════════════════════════════════════════════════════╝

        # 🔍 PALO ALTO NETWORKS SECURITY SCAN DEBUG INFORMATION
        print(f"🛡️ PALO ALTO NETWORKS SECURITY SCAN DETAILS:")
        print(f"   🚦 Security Category: {scan_result.get('category')}")                    # 🛡️ Overall security classification
        print(f"   📋 Security Action: {scan_result.get('action')}")                        # 🚦 Recommended security action
        print(f"   🎯 PROMPT detections: {scan_result.get('prompt_detected', {})}")        # 🚨 Threats in user's message
        print(f"   📤 RESPONSE detections: {scan_result.get('response_detected', {})}")    # 🚨 Threats in the LLM output (if sent)

        # ╔══════════════════════════════════════════════════════════════════════╗
        # ║            🎯 INPUT SECURITY THREAT ANALYSIS                         ║
        # ║  Analyzes threats found in the USER'S MESSAGE (not the chatbot)     ║
        # ╚══════════════════════════════════════════════════════════════════════╝
        
        # 🎯 ANALYZE USER INPUT FOR SECURITY THREATS
        prompt_detected = scan_result.get('prompt_detected', {})  # 🚨 Security threats in user's message
        if prompt_detected:
            print(f"\n🎯 USER MESSAGE SECURITY THREATS:")
            for threat_type, detected in prompt_detected.items():
                if detected:
                    # 📚 TRANSLATE SECURITY CODES TO HUMAN LANGUAGE
                    threat_name = self.threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"   🔴 {threat_name} detected in user's message")
                    threats_found = True  # 🚨 Flag that security threats exist

                    # 💡 PROVIDE SPECIFIC SECURITY GUIDANCE FOR EACH THREAT
                    if threat_type in ['injection', 'prompt_injection']:
                        print(f"      └─ 🚫 SECURITY ISSUE: Malicious AI instruction patterns detected")
                        print(f"      └─ 💡 SECURITY FIX: Rephrase without command-like language")
                    elif threat_type == 'agent':
                        print(f"      └─ 🚫 SECURITY ISSUE: AI agent manipulation attempt detected")
                        print(f"      └─ 💡 SECURITY FIX: Remove role-playing or identity claims")
                    elif threat_type in ['toxicity', 'toxic_content']:
                        print(f"      └─ 🚫 SECURITY ISSUE: Harmful or offensive content identified")
                        print(f"      └─ 💡 SECURITY FIX: Use respectful, appropriate language")
                    elif threat_type == 'url_cats':
                        print(f"      └─ 🚫 SECURITY ISSUE: Malicious URL detected in message")
                        print(f"      └─ 💡 SECURITY FIX: Remove suspicious links")
                    elif threat_type == 'dlp':
                        print(f"      └─ 🚫 SECURITY ISSUE: Sensitive data exposure risk")
                        print(f"      └─ 💡 SECURITY FIX: Remove personal/confidential information")

        # ╔══════════════════════════════════════════════════════════════════════════╗
        # ║                📤 RESPONSE THREAT DETECTION ANALYSIS                    ║
        # ║                                                                          ║
        # ║  Only populated on the second scan of a turn, when the Claude reply was ║
        # ║  included in the request. It reports what Palo Alto found in the        ║
        # ║  model's actual output: leaked sensitive data, malicious URLs or code,  ║
        # ║  toxic content, or a dangerous database query. A block verdict here     ║
        # ║  means the chatbot withholds the reply.                                 ║
        # ╚══════════════════════════════════════════════════════════════════════════╝

        # 📤 ANALYZE THE LLM RESPONSE FOR SECURITY THREATS
        response_detected = scan_result.get('response_detected', {})  # 📤 Threats found in the LLM output we sent
        if response_detected:
            print(f"\n📤 CLAUDE RESPONSE THREATS:")
            for threat_type, detected in response_detected.items():
                if detected:
                    # 📚 TRANSLATE SECURITY CODES TO HUMAN-FRIENDLY LANGUAGE
                    threat_name = self.threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"   🔴 RESPONSE THREAT: {threat_name} found in AI output")
                    threats_found = True  # 🚨 Flag that security threats were found

                    # 💡 PROVIDE DETAILED GUIDANCE FOR RESPONSE-LEVEL THREATS
                    if threat_type == 'url_cats' and detected:
                        print(f"      └─ 🌐 The reply contains a URL in a blocked category")
                    elif threat_type == 'dlp' and detected:
                        print(f"      └─ 🔒 The reply contains sensitive data matched by the DLP profile")
                    elif threat_type in ['toxicity', 'toxic_content'] and detected:
                        print(f"      └─ 💬 The reply contains harmful or offensive content")
                    elif threat_type == 'malicious_code' and detected:
                        print(f"      └─ 💻 The reply contains malicious code")
                    elif threat_type == 'db_security' and detected:
                        print(f"      └─ 🗄️ The reply contains a database query your profile blocks")
                    else:
                        print(f"      └─ ⚠️ The reply violates the security profile")

        # ╔══════════════════════════════════════════════════════════════════════╗
        # ║              🚦 FINAL SECURITY ASSESSMENT                           ║
        # ║  Overall security verdict from Palo Alto Networks analysis          ║
        # ╚══════════════════════════════════════════════════════════════════════╝
        
        # 🚦 OVERALL SECURITY THREAT ASSESSMENT
        if scan_result.get('category') == 'malicious' and not threats_found:
            print(f"   🔴 GENERAL SECURITY POLICY VIOLATION")
            print(f"      └─ 🛡️ SECURITY: Content flagged as malicious by Palo Alto policies")
            threats_found = True  # 🚨 Mark that security threats were found

        # ✅ SECURITY ALL-CLEAR STATUS
        if not threats_found:
            print("   ✅ No security threats detected by Palo Alto Networks")
            print("   ✅ Content approved for safe AI processing")

        print("=" * 50)  # 📊 Close security results section


async def main():
    """
    🚀 MAIN ASYNC CHATBOT CONTROLLER WITH PYTHON SDK
    
    WHAT THIS FUNCTION DOES:
    This is the "mission control" for your secure chatbot. It coordinates between
    the Palo Alto Networks security scanning and Claude AI processing to 
    create a bulletproof, intelligent chatbot experience.

    Demonstrates development/testing usage of the Palo Alto Networks
    AI Security Python SDK with comprehensive scanning capabilities.
    """

    print("🚀 INITIALIZING PYTHON SDK SECURE AI CHATBOT")
    print("=" * 60)
    print("Security Layer: Palo Alto Networks AI Security Python SDK")
    print("AI Processing: Anthropic Claude Models")
    print("Features: Python SDK, Async/Sync, Enhanced Error Handling")
    print("=" * 60)

    if not SDK_AVAILABLE:
        print("\n❌ PYTHON SDK UNAVAILABLE")
        print("   Install with: pip install pan-aisecurity")
        return

    # CREDENTIAL VALIDATION
    print("\n🔑 VALIDATING CREDENTIALS...")

    pan_api_key = os.getenv("PANW_AI_SEC_API_KEY")
    pan_ai_profile_name = os.getenv("PANW_AI_SEC_PROFILE_NAME")

    if not pan_api_key:
        print("❌ ERROR: Missing PANW_AI_SEC_API_KEY environment variable")
        return

    if not pan_ai_profile_name:
        print("❌ ERROR: Missing PANW_AI_SEC_PROFILE_NAME environment variable")
        return

    print("✅ Palo Alto Networks credentials validated")

    # CLAUDE VALIDATION
    claude_key = os.getenv("ANTHROPIC_API_KEY")

    if not claude_key:
        print("❌ ERROR: Missing ANTHROPIC_API_KEY environment variable")
        print("   Get your API key from: https://console.anthropic.com/")
        return

    print("✅ Claude AI credentials validated")

    # INITIALIZE SDK SCANNER
    print("\n🛡️ INITIALIZING PYTHON SDK SCANNER...")

    try:
        scanner = SDKSecurityScanner(
            api_key=pan_api_key,
            profile_name=pan_ai_profile_name,
            num_retries=3
        )
        print("✅ Python SDK Scanner initialized successfully")
        print(f"   API Endpoint: {scanner.config.api_endpoint}")
        print(f"   Profile: {scanner.profile_name}")
        print(f"   Retries: {scanner.config.num_retries}")
    except Exception as e:
        print(f"❌ Failed to initialize SDK Scanner: {e}")
        return

    # INITIALIZE CLAUDE AI CLIENT
    print("\n🧠 INITIALIZING CLAUDE AI CLIENT...")

    claude_client = None

    try:
        claude_client = Anthropic(
            api_key=claude_key
        )
        print("✅ Claude AI client initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize Claude AI client: {e}")
        print("   Claude functionality will be unavailable")
        print("   Note: The security scanning will still work perfectly!")
        claude_client = None

    # INTERACTIVE CHAT LOOP
    print("\n" + "=" * 60)
    print("PYTHON SDK CHATBOT READY")
    print("=" * 60)
    print("Features:")
    print("• Palo Alto Networks AI Security Python SDK")
    print("• Development/testing threat detection and analysis")
    print("• Async scanning with intelligent retry logic")
    print("• Comprehensive security insights and recommendations")
    print("• Powered by Claude AI for intelligent responses")
    print("• Type 'exit' to terminate")

    while True:
        user_input = input("\n👤 You: ").strip()

        if user_input.lower() == 'exit':
            print("\n👋 SDK session terminated. Goodbye!")
            break

        if not user_input:
            print("⚠️  Please enter a non-empty message.")
            continue

        # PYTHON SDK SECURITY SCANNING
        print("\n🔒 PYTHON SDK SECURITY SCANNING")
        print("=" * 50)

        try:
            # Perform async security scan using SDK
            scan_result = await scanner.async_scan(user_input)

            # Display comprehensive results
            scanner.display_enhanced_results(scan_result)

            # SECURITY DECISION PROCESSING
            category = scan_result.get('category')
            action = scan_result.get('action')

            print(f"\n🚦 SECURITY DECISION:")
            print(f"   Classification: {category}")
            print(f"   Recommended Action: {action}")

            if category == "malicious" or action == "block":
                # MESSAGE BLOCKED
                print("\n🚫 MESSAGE BLOCKED BY SDK SECURITY")
                print("=" * 50)
                print(f"Security Status: {category.upper()}")
                print(f"Action Taken: {action.upper()}")
                print(f"Scan Time: {scan_result.get('scan_time_ms', 0):.1f}ms")
                print("\n🤖 SDK Response: This message cannot be processed due to")
                print("   security policy violations detected by the Palo Alto Networks")
                print("   AI Security Python SDK. Please review the detailed threat")
                print("   analysis above and modify your message accordingly.")
                print("=" * 50)

            elif category == "benign" and action == "allow":
                # MESSAGE APPROVED
                print("\n✅ SDK SECURITY CHECK PASSED")
                print("=" * 50)
                print(f"Security Status: {category.upper()}")
                print(f"Action: {action.upper()}")
                print(f"Scan Time: {scan_result.get('scan_time_ms', 0):.1f}ms")
                print("SDK analysis confirms content is safe for AI processing...")
                print("=" * 50)

                # AI PROCESSING
                if claude_client:
                    print("\n🧠 AI PROCESSING PHASE")
                    print("=" * 50)
                    print("Generating Claude response...")

                    try:
                        response = claude_client.messages.create(
                            model=CLAUDE_MODEL,  # Claude model ID, defaults to claude-sonnet-5-5
                            max_tokens=800,
                            # No temperature: the anthropic SDK dropped the
                            # parameter in 2.x and raises TypeError if passed.
                            messages=[
                                {
                                    "role": "user",
                                    "content": user_input
                                }
                            ]
                        )

                        ai_response = "".join(
                            block.text for block in response.content if getattr(block, "type", "") == "text")

                        # 🛡️ SCAN THE RESPONSE BEFORE SHOWING IT
                        # The model output goes back to Palo Alto with the prompt so
                        # leaked data, malicious URLs or code, toxic content, and
                        # dangerous SQL in the reply are caught before display.
                        print("\n🔒 PYTHON SDK RESPONSE SCANNING")
                        print("=" * 50)
                        response_scan = await scanner.async_scan(user_input, ai_response)
                        scanner.display_enhanced_results(response_scan)

                        if response_scan.get("category") == "malicious" or response_scan.get("action") == "block":
                            print("\n🚫 AI RESPONSE BLOCKED BY SDK SECURITY")
                            print("=" * 50)
                            print(f"Security Status: {str(response_scan.get('category')).upper()}")
                            print(f"Action Taken: {str(response_scan.get('action')).upper()}")
                            print("\n🤖 SDK Response: The AI generated a reply that violates the")
                            print("   security profile, so it was withheld.")
                            print("=" * 50)
                        else:
                            print("\n" + "=" * 60)
                            print("🤖 CLAUDE RESPONSE:")
                            print("=" * 60)
                            print(ai_response)
                            print("=" * 60)

                    except Exception as claude_err:
                        print(f"\n❌ CLAUDE ERROR: {claude_err}")
                        print(
                            "🤖 Response: A technical error occurred during AI processing.")
                else:
                    print("\n⚠️  CLAUDE UNAVAILABLE")
                    print(
                        "🤖 Response: Message passed security screening, but AI processing unavailable.")

            else:
                print(f"\n⚠️  UNEXPECTED SECURITY RESULT")
                print(f"   Category: {category}")
                print(f"   Action: {action}")

        except AISecSDKException as sdk_err:
            print(f"\n❌ SDK ERROR: {sdk_err}")
            print("🤖 Response: SDK security scanning encountered an issue.")

        except Exception as general_err:
            print(f"\n❌ UNEXPECTED ERROR: {general_err}")
            print("🤖 Response: An unexpected error occurred during processing.")


if __name__ == "__main__":
    """Python SDK Entry Point"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Python SDK chatbot terminated by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("Please check your configuration and try again.")