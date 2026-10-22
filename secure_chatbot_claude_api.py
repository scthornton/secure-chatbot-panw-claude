# ===========================================================================
# DEVELOPMENT/TESTING CHATBOT WITH PALO ALTO NETWORKS API INTEGRATION
# ===========================================================================
# ⚠️ DISCLAIMER: This is NOT an official Palo Alto Networks tool!
# This is an independent development project for testing API integration.
# Palo Alto Networks provides NO support for this tool.
# You are responsible for all testing, validation, and security.
#
# PURPOSE: Demonstrates integration between Palo Alto Networks AI Security API
# and Anthropic Claude AI for development and testing purposes only.
#
# WORKFLOW: User Input → Security Scan → Claude AI Processing → Response
# ===========================================================================

# Import required libraries
import requests  # For making HTTP requests to web APIs
import json      # For converting Python data to/from JSON format
import os        # For reading environment variables from system
import uuid      # For generating unique transaction IDs
import getpass   # For a stable app_user value in scan metadata
from anthropic import Anthropic  # Official Anthropic library for Claude API

# Load credentials from a .env file if one is present. python-dotenv handles
# quoting, blank lines, and "export VAR=..." syntax, and real environment
# variables always win over .env values (the previous hand-rolled loader did
# the opposite and silently overwrote exported variables).
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
# Cloud Manager session and violation views, so set them to something you can
# recognize when you look at the logs.
APP_NAME = os.getenv("PANW_AI_SEC_APP_NAME", "secure-chatbot-claude")
APP_USER = os.getenv("PANW_AI_SEC_APP_USER", getpass.getuser())


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                    🛡️ PALO ALTO NETWORKS SECURITY SECTION                 ║
# ║                                                                            ║
# ║ ⚠️  IMPORTANT: THIS ENTIRE FUNCTION IS PURE SECURITY - NOT CHATBOT!       ║
# ║                                                                            ║
# ║ What happens here:                                                         ║
# ║ 1. Takes your message and sends it to Palo Alto's security servers        ║
# ║ 2. Palo Alto analyzes the message for threats and dangers                 ║
# ║ 3. Returns a "report card" saying if the message is safe or dangerous     ║
# ║ 4. This happens BEFORE any AI chatbot processing                          ║
# ║                                                                            ║
# ║ Think of it like: SECURITY CHECKPOINT → Then maybe chatbot                ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def scan_prompt_with_paloalto_api(prompt, api_key, ai_profile_name, base_url=None, response=None):
    """
    🛡️ SECURITY SCANNER FUNCTION - THE GUARDIAN OF YOUR CHATBOT

    WHAT THIS FUNCTION DOES:
    Think of this function as a security guard that examines every message before
    it reaches the AI. Just like airport security checks your luggage, this function
    checks your text messages for any dangerous or inappropriate content.

    It is called twice per turn: once with only the user's prompt (before the
    LLM sees it) and once with the prompt plus the LLM's response (before the
    user sees it). Pass the model output in `response` for the second call.
    Prisma AIRS evaluates a response only when you send one; it does not
    predict what the model will say.

    HOW IT PROTECTS YOU:
    1. 🔍 SCANS every word and phrase in your message
    2. 🚨 DETECTS various types of threats and harmful content
    3. ✅ APPROVES safe messages to continue to the AI
    4. 🚫 BLOCKS dangerous messages before they cause problems

    TYPES OF THREATS IT CATCHES:
    - 💳 Personal Information: Credit cards, social security numbers, passwords
    - 🎭 Manipulation Attempts: Tricks trying to make the AI misbehave  
    - 🔗 Dangerous Links: Suspicious websites that could be harmful
    - 🤬 Toxic Content: Hate speech, harassment, inappropriate material
    - 💻 Malicious Code: Attempts to inject harmful computer instructions

    WHAT YOU NEED TO PROVIDE:
    - prompt: The message you want to check (like "Hello, how are you?")
    - api_key: Your secret password to access Palo Alto's security service
    - ai_profile_name: The name of your security ruleset/configuration
    - base_url: The web address of Palo Alto's security servers (defaults to
      PANW_AI_SEC_ENDPOINT, which defaults to the US region)
    - response: Optional LLM output to scan together with the prompt

    WHAT YOU GET BACK:
    - A detailed report telling you if the message is safe or dangerous
    - Specific information about any threats found
    - A recommendation to either "allow" or "block" the message
    """

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🌐 STEP 1: BUILD THE SECURITY API CONNECTION
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # This part figures out WHERE to send your message for security scanning.
    # It's like writing the address on an envelope before mailing it.
    base_url = (base_url or PANW_AI_SEC_ENDPOINT).rstrip("/")
    url = f"{base_url}/v1/scan/sync/request"

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🏷️ STEP 2: CREATE A TRACKING NUMBER FOR THIS SECURITY SCAN
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Every security scan gets a unique ID number, like a tracking number for a package.
    # This helps Palo Alto's servers keep track of your specific security request.
    # If something goes wrong, support can use this ID to find exactly what happened.
    transaction_id = str(uuid.uuid4())
    print(f"Generated transaction ID: {transaction_id}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 📋 STEP 3: PREPARE THE SECURITY REQUEST HEADERS  
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Headers are like the "delivery instructions" on a package.
    # They tell Palo Alto's security servers how to handle our request.
    headers = {
        "Content-Type": "application/json",  # 📄 "This package contains JSON data"
        "Accept": "application/json",        # 📨 "Please send JSON data back to me"
        "x-pan-token": api_key              # 🔐 "Here's my secret password to prove I'm authorized"
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 📦 STEP 4: PACKAGE YOUR MESSAGE FOR SECURITY ANALYSIS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # This creates the actual "package" we're sending to Palo Alto's security service.
    # It contains your message plus information about what security rules to apply.
    content = {"prompt": prompt}           # 💬 Your actual message that needs security checking
    if response is not None:
        content["response"] = response     # 📤 The LLM's reply, when scanning the second half of the turn

    payload = {
        "tr_id": transaction_id,           # 🏷️ The tracking number we created above
        "ai_profile": {                    # 🛡️ Which security ruleset to use
            "profile_name": ai_profile_name  # This tells Palo Alto which security rules you want applied
        },
        "metadata": {                      # 🏢 Who is calling, shown in the SCM session and violation views
            "app_name": APP_NAME,
            "app_user": APP_USER,
            "ai_model": CLAUDE_MODEL
        },
        "contents": [content]              # 📝 The actual content to be scanned
    }

    # Display what we're about to scan
    what = "prompt + response" if response is not None else "prompt"
    print(f"\n🔍 Scanning {what} for security threats...")
    print(f"   Content: '{prompt[:50]}...' ({len(prompt)} characters)")

    try:
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 🚀 STEP 5: SEND YOUR MESSAGE TO PALO ALTO'S SECURITY INSPECTION
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # This is the actual moment where your message gets sent to Palo Alto Networks
        # for security analysis. Think of it like putting your package in the mail
        # and sending it to a security inspection facility. The timeout stops the
        # chatbot from hanging forever if the network path is broken.
        api_response = requests.post(url, headers=headers, json=payload, timeout=30)

        # ✅ Check if Palo Alto's servers responded successfully
        # If they return an error code (like 401 Unauthorized or 500 Server Error),
        # this line will detect it and trigger the error handling below.
        api_response.raise_for_status()

        # 📊 Convert Palo Alto's response from JSON text back to Python data
        # Palo Alto sends back their analysis results as JSON text. This line
        # converts that text back into a Python dictionary we can work with.
        scan_result = api_response.json()

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 📊 STEP 6: PROCESS PALO ALTO'S SECURITY ANALYSIS RESULTS
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # At this point, Palo Alto Networks has analyzed your message and sent back
        # a detailed "report card" about any security threats they found.
        # Let's display this information in a human-readable format.
        
        print("\n📋 SECURITY SCAN RESULTS:")
        print("=" * 40)
        # 🏷️ OVERALL CLASSIFICATION: This is Palo Alto's main verdict about your message
        # - "benign" = SAFE: Your message is okay to send to the AI
        # - "malicious" = DANGEROUS: Your message contains threats and should be blocked
        print(f"Overall Classification: {scan_result.get('category', 'Unknown')}")
        
        # 🚦 RECOMMENDED ACTION: This is what Palo Alto thinks you should do
        # - "allow" = GO AHEAD: Send this message to the AI chatbot
        # - "block" = STOP: Do not send this message to the AI chatbot
        print(f"Recommended Action: {scan_result.get('action', 'Unknown')}")

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 🔍 STEP 7: ANALYZE SPECIFIC THREATS DETECTED BY PALO ALTO  
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # If Palo Alto found specific threats, this section will explain exactly
        # what they found and why it's dangerous. This helps you understand
        # what to change in your message to make it safe.
        print("\n⚠️  SPECIFIC THREATS IDENTIFIED:")
        print("=" * 40)

        # Define threat category mappings for better display
        threat_categories = {
            # Prompt-based threats
            'prompt_injection': 'Prompt Injection Attack',
            'injection': 'Prompt Injection Attack',  # Alternative naming
            'jailbreak': 'Jailbreak Attempt',
            'malicious_code': 'Malicious Code Generation',
            'sensitive_data': 'Sensitive Data Exposure',
            'toxicity': 'Toxic Content',
            'bias': 'Bias Detection',
            'harmful_content': 'Harmful Content',

            # Response-based threats
            'url_cats': 'Malicious URL Detection',
            'malware': 'Malware Detection',
            'db_security': 'Database Security Threat',
            'dlp': 'Data Loss Prevention',
            'pii': 'Personal Identifiable Information',
            'financial_data': 'Financial Data Exposure',
            'intellectual_property': 'Intellectual Property Risk',
            'code_injection': 'Code Injection',
            'resource_overload': 'Resource Overload/DoS',
            'hallucination': 'AI Hallucination',
        }

        threats_found = False

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
        # ║  twice: prompt first, then prompt + response before anything is shown.   ║
        # ║                                                                          ║
        # ║  The two sides also run different detectors. Prompt injection and agent  ║
        # ║  protection are prompt-side only; database security is response-side    ║
        # ║  only. A detector that is disabled in the profile is absent from the     ║
        # ║  map, not false.                                                         ║
        # ╚══════════════════════════════════════════════════════════════════════════╝

        # 🔍 PALO ALTO API RESPONSE STRUCTURE DEBUG
        print(f"🔍 PALO ALTO SECURITY API RESPONSE:")
        print(f"   🛡️ Security Category: {scan_result.get('category')}")                  # Overall security verdict
        print(f"   📋 Security Action: {scan_result.get('action')}")                       # What should happen next
        print(f"   🆔 Scan ID: {scan_result.get('scan_id')}  Report ID: {scan_result.get('report_id')}")
        print(f"   🎯 PROMPT detections: {scan_result.get('prompt_detected', {})}")        # Threats in user's message
        print(f"   📤 RESPONSE detections: {scan_result.get('response_detected', {})}")    # Threats in the LLM output (if sent)

        # Check for prompt-based threats
        prompt_detected = scan_result.get('prompt_detected', {})
        if prompt_detected:
            for threat_type, detected in prompt_detected.items():
                if detected:
                    threat_name = threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"🔴 PROMPT THREAT: {threat_name}")
                    threats_found = True

        # ╔══════════════════════════════════════════════════════════════════════════╗
        # ║                📤 RESPONSE THREAT DETECTION ANALYSIS                    ║
        # ║                                                                          ║
        # ║  This block only has content on the second scan of a turn, when the     ║
        # ║  LLM's reply was included in the request. It tells you what Palo Alto   ║
        # ║  found in the model's output: leaked sensitive data, malicious URLs or  ║
        # ║  code, toxic content, or a dangerous database query. If any of these    ║
        # ║  come back with a block action, the chatbot withholds the reply.        ║
        # ╚══════════════════════════════════════════════════════════════════════════╝

        # 📤 ANALYZE THE LLM RESPONSE FOR SECURITY THREATS
        response_detected = scan_result.get('response_detected', {})  # 📤 Threats found in the LLM output we sent
        if response_detected:
            print(f"\n📤 AI RESPONSE THREATS:")
            for threat_type, detected in response_detected.items():
                if detected:
                    threat_name = threat_categories.get(
                        threat_type, threat_type.replace('_', ' ').title())
                    print(f"🔴 RESPONSE THREAT: {threat_name}")
                    threats_found = True

                    # 💡 PROVIDE SPECIFIC GUIDANCE FOR RESPONSE-LEVEL THREATS
                    if threat_type == 'url_cats' and detected:
                        print(f"   └─ 🌐 RESPONSE ISSUE: the AI reply contains a malicious URL")
                    elif threat_type == 'db_security' and detected:
                        print(f"   └─ 🗄️ RESPONSE ISSUE: the AI reply contains a database query your profile blocks")
                    elif threat_type == 'dlp' and detected:
                        print(f"   └─ 🔒 RESPONSE ISSUE: the AI reply contains sensitive data")
                    elif threat_type in ['toxicity', 'toxic_content'] and detected:
                        print(f"   └─ 💬 RESPONSE ISSUE: the AI reply contains harmful or offensive content")
                    elif threat_type == 'malicious_code' and detected:
                        print(f"   └─ 💻 RESPONSE ISSUE: the AI reply contains malicious code")
                    else:
                        print(f"   └─ ⚠️ RESPONSE ISSUE: the AI reply violates the security profile")

        # Check for additional threat indicators
        if scan_result.get('category') == 'malicious' and not threats_found:
            print(f"🔴 GENERAL THREAT: Content classified as malicious")
            threats_found = True

        if not threats_found:
            print("✅ No specific threats detected")
        print("=" * 40)
        return scan_result

    # Handle different types of HTTP and network errors
    except requests.exceptions.HTTPError as http_err:
        # Server returned an error status code (4xx or 5xx)
        print(f"❌ HTTP Error: {http_err}")
        print(f"   Server Response: {http_err.response.text}")
        print("   This typically indicates authentication issues or server problems")
        return None

    except requests.exceptions.ConnectionError as conn_err:
        # Could not establish connection to the server
        print(f"❌ Connection Error: {conn_err}")
        print("   Check your internet connection and firewall settings")
        return None

    except requests.exceptions.Timeout as timeout_err:
        # Request took too long to complete
        print(f"❌ Timeout Error: {timeout_err}")
        print("   The API server is not responding within the expected time")
        return None

    except requests.exceptions.RequestException as req_err:
        # Any other request-related error
        print(f"❌ Request Error: {req_err}")
        print("   An unexpected network error occurred")
        return None

    except json.JSONDecodeError as json_err:
        # Server response was not valid JSON
        print(f"❌ JSON Decode Error: {json_err}")
        print(f"   Raw Response: {api_response.text}")
        print("   The server returned malformed data")
        return None


def main():
    """
    🚀 MAIN CHATBOT CONTROLLER - THE BRAIN OF THE OPERATION
    
    WHAT THIS FUNCTION DOES (STEP BY STEP):
    Think of this as the "control center" that manages everything the chatbot does.
    It's like the conductor of an orchestra, making sure every part plays at the right time.

    THE COMPLETE WORKFLOW:
    1. 🔑 SETUP PHASE: Checks that you have all the required passwords and settings
       - Verifies your Palo Alto Networks security credentials
       - Verifies your Claude AI credentials  
       - Makes sure everything is properly configured

    2. 🧠 INITIALIZATION PHASE: Starts up all the necessary services
       - Connects to Palo Alto's security scanning service
       - Connects to Claude AI service
       - Prepares everything for chatting

    3. 💬 CHAT LOOP PHASE: Handles the actual conversation
       - Waits for you to type a message
       - Sends your message through security screening first
       - If safe: forwards to Claude AI for a smart response
       - If dangerous: blocks the message and warns you

    🛡️ SECURITY-FIRST ARCHITECTURE:
    This chatbot follows a "guilty until proven innocent" approach:
    - EVERY message goes through security scanning first (no exceptions!)
    - Dangerous messages are immediately blocked (better safe than sorry!)  
    - Only verified-safe messages get processed by Claude AI
    - No chat history is saved (keeps things private and secure)
    
    WHY THIS APPROACH MATTERS:
    - Prevents malicious users from tricking the AI into harmful behavior
    - Protects against data leaks and privacy violations  
    - Ensures the AI only responds to appropriate, safe requests
    - Maintains a clean, professional interaction environment
    """

    print("🧪 INITIALIZING DEVELOPMENT/TESTING AI CHATBOT")
    print("=" * 60)
    print("⚠️ DISCLAIMER: NOT officially supported by Palo Alto Networks!")
    print("🛡️ Security Layer: Palo Alto Networks Runtime Security API (testing)")
    print("🧠 AI Processing: Anthropic Claude Models")
    print("=" * 60)
    print("\nConfiguration: Each message is independently scanned")
    print("No conversation history is stored for enhanced security")

    # ╔════════════════════════════════════════════════════════════════════════════╗
    # ║              🔐 PALO ALTO NETWORKS CREDENTIAL VALIDATION                   ║
    # ║                                                                            ║
    # ║ ⚠️  SECURITY COMPONENT: This section checks your Palo Alto credentials    ║
    # ║                                                                            ║
    # ║ What's happening: We're making sure you have the right "keys" to access   ║
    # ║ Palo Alto's security scanning service. Without these credentials, the     ║
    # ║ security scanning won't work and messages won't be protected.             ║
    # ╚════════════════════════════════════════════════════════════════════════════╝
    print("\n🔑 VALIDATING SECURITY CREDENTIALS...")

    # Retrieve Palo Alto Networks API credentials from environment
    pan_api_key = os.getenv("PANW_AI_SEC_API_KEY")
    pan_ai_profile_name = os.getenv("PANW_AI_SEC_PROFILE_NAME")

    # Validate Palo Alto Networks credentials are present
    if not pan_api_key:
        print("❌ ERROR: Missing PANW_AI_SEC_API_KEY environment variable")
        print("   This variable must contain your Palo Alto Networks API key")
        print("   Set it using: export PANW_AI_SEC_API_KEY='your-api-key'")
        return

    if not pan_ai_profile_name:
        print("❌ ERROR: Missing PANW_AI_SEC_PROFILE_NAME environment variable")
        print("   This variable must contain your AI Security Profile name")
        print("   Set it using: export PANW_AI_SEC_PROFILE_NAME='profile-name'")
        return

    print("✅ Palo Alto Networks credentials validated")

    # ╔════════════════════════════════════════════════════════════════════════════╗
    # ║                   🤖 CLAUDE AI CREDENTIAL VALIDATION                       ║
    # ║                                                                            ║
    # ║ 🧠 CHATBOT COMPONENT: This section checks your Anthropic credentials      ║
    # ║                                                                            ║
    # ║ What's happening: We're verifying you have access to Claude AI            ║
    # ║ service. This is what will generate intelligent responses to your         ║
    # ║ messages AFTER they pass Palo Alto's security screening.                  ║
    # ║                                                                            ║
    # ║ Note: Without Claude credentials, security scanning still works,          ║
    # ║ but you won't get AI responses to your safe messages.                     ║
    # ╚════════════════════════════════════════════════════════════════════════════╝
    print("\n🔑 VALIDATING CLAUDE AI CREDENTIALS...")

    # Claude API key
    claude_key = os.getenv("ANTHROPIC_API_KEY")

    # Validate Claude API key is present
    if not claude_key:
        print("❌ ERROR: Missing ANTHROPIC_API_KEY environment variable")
        print("   This variable must contain your Claude API key")
        print("   Set it using: export ANTHROPIC_API_KEY='your-api-key'")
        print("   Get your API key from: https://console.anthropic.com/")
        return

    print("✅ Claude AI credentials validated")

    # ╔════════════════════════════════════════════════════════════════════════════╗
    # ║                    🧠 CLAUDE AI CLIENT INITIALIZATION                      ║
    # ║                                                                            ║
    # ║ 🤖 CHATBOT COMPONENT: This section sets up the AI chatbot brain           ║
    # ║                                                                            ║
    # ║ What's happening: We're connecting to Claude's AI service so that         ║
    # ║ when messages pass security screening, we can get intelligent responses.   ║
    # ║                                                                            ║
    # ║ Important: This AI connection only gets used AFTER Palo Alto says a       ║
    # ║ message is safe. Dangerous messages never reach this AI system.           ║
    # ║                                                                            ║
    # ║ Think of it like: Security Guard → (if safe) → Smart AI Assistant         ║
    # ╚════════════════════════════════════════════════════════════════════════════╝
    print("\n🧠 INITIALIZING CLAUDE AI CLIENT...")

    claude_client = None

    try:
        # Initialize the Claude client using official Anthropic library
        claude_client = Anthropic(
            api_key=claude_key
        )
        print("✅ Claude AI client initialized successfully")

    except Exception as e:
        # Handle client initialization failures
        print(f"❌ Failed to initialize Claude AI client: {e}")
        print("   Claude functionality will be unavailable")
        print("   Note: The security scanning will still work perfectly!")
        claude_client = None

    # INTERACTIVE CHAT LOOP INITIALIZATION
    print("\n" + "=" * 60)
    print("CHATBOT READY FOR INTERACTION")
    print("=" * 60)
    print("Commands:")
    print("• Type your message and press Enter to chat")
    print("• Type 'exit' to terminate the program")
    print("• All messages undergo security scanning before AI processing")

    # ╔════════════════════════════════════════════════════════════════════════════╗
    # ║                       💬 MAIN CHAT CONVERSATION LOOP                       ║
    # ║                                                                            ║
    # ║ 🔄 WORKFLOW ORCHESTRATOR: This is where everything comes together         ║
    # ║                                                                            ║
    # ║ The Big Picture:                                                           ║
    # ║ 1. 👤 User types a message                                                 ║
    # ║ 2. 🛡️ SECURITY: Message goes to Palo Alto for threat scanning            ║
    # ║ 3. 📊 DECISION: Based on Palo Alto's analysis, we either:                ║
    # ║    - 🚫 Block dangerous messages (with explanation)                       ║
    # ║    - ✅ Send safe messages to Claude AI for an intelligent response       ║
    # ║ 4. 🔄 Repeat forever until user types "exit"                              ║
    # ║                                                                            ║
    # ║ Key Security Point: The AI NEVER sees dangerous messages!                 ║
    # ╚════════════════════════════════════════════════════════════════════════════╝
    
    # Main conversation loop - continues until user exits
    while True:
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 👤 STEP 1: GET USER'S MESSAGE
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Wait for the user to type something and clean up any extra spaces
        user_input = input("\n👤 You: ").strip()

        # Check for exit command - allows user to quit gracefully
        if user_input.lower() == 'exit':
            print("\n👋 Session terminated. Goodbye!")
            break

        # Don't process empty messages - ask user to type something
        if not user_input:
            print("⚠️  Please enter a non-empty message.")
            continue

        # ╔══════════════════════════════════════════════════════════════════════════╗
        # ║                      🛡️ SECURITY SCANNING PHASE                         ║
        # ║                                                                          ║
        # ║ ⚠️  CRITICAL SECURITY STEP: This is where Palo Alto checks your message ║
        # ║                                                                          ║
        # ║ What happens:                                                            ║
        # ║ 1. Your message gets sent to Palo Alto's security servers               ║
        # ║ 2. Their AI analyzes it for threats, dangers, and policy violations     ║
        # ║ 3. They send back a detailed security report                            ║
        # ║ 4. We use that report to decide if the message is safe for the chatbot  ║
        # ║                                                                          ║
        # ║ NO CHATBOT PROCESSING HAPPENS UNTIL SECURITY APPROVAL!                  ║
        # ╚══════════════════════════════════════════════════════════════════════════╝
        print("\n🔒 SECURITY SCANNING PHASE")
        print("=" * 50)

        # 🛡️ SEND MESSAGE TO PALO ALTO NETWORKS FOR THREAT ANALYSIS
        # This function call is what actually performs the security scanning.
        # Everything that happens inside scan_prompt_with_paloalto_api() is pure security.
        scan_result = scan_prompt_with_paloalto_api(
            user_input, pan_api_key, pan_ai_profile_name)

        # ╔══════════════════════════════════════════════════════════════════════════╗
        # ║                    📊 SECURITY DECISION PROCESSING                       ║
        # ║                                                                          ║
        # ║ 🛡️ SECURITY COMPONENT: Processing Palo Alto's security analysis        ║
        # ║                                                                          ║
        # ║ What's happening: Palo Alto has finished analyzing your message and     ║
        # ║ sent back their security verdict. Now we need to decide what to do      ║
        # ║ based on their recommendation.                                           ║
        # ║                                                                          ║
        # ║ The Decision Tree:                                                       ║
        # ║ - If Palo Alto says "malicious" or "block" → 🚫 Block the message      ║
        # ║ - If Palo Alto says "benign" and "allow" → ✅ Send to Claude AI       ║
        # ║ - If something unexpected → ⚠️ Show warning and ask user to retry       ║
        # ╚══════════════════════════════════════════════════════════════════════════╝
        if scan_result:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # 🔍 EXTRACT PALO ALTO'S SECURITY VERDICT
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # Palo Alto sends back two key pieces of information:
            
            # 🏷️ CATEGORY: Is the message safe or dangerous?
            category = scan_result.get('category')  # Expected: 'benign' (safe) or 'malicious' (dangerous)
            
            # 🚦 ACTION: What should we do with this message?
            action = scan_result.get('action')      # Expected: 'allow' (send to AI) or 'block' (stop here)

            print(f"\n🚦 SECURITY ASSESSMENT:")
            print(f"   Classification: {category}")
            print(f"   Recommended Action: {action}")

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # 🚫 SECURITY DECISION: BLOCK DANGEROUS MESSAGES  
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # If Palo Alto detected threats, we STOP HERE and don't send anything to the AI.
            # This is the security "firewall" in action - protecting the AI from harmful input.
            if category == "malicious" or action == "block":
                # MESSAGE BLOCKED - Security threat detected
                print("\n🚫 MESSAGE BLOCKED BY SECURITY")
                print("=" * 40)
                print(f"Security Status: {category.upper()}")
                print(f"Action Taken: {action.upper()}")
                print("\n🤖 Response: This message cannot be processed due to")
                print("   security policy violations. Please modify your")
                print("   message and try again.")
                print("=" * 40)

            elif category == "benign" and action == "allow":
                # MESSAGE APPROVED - Safe to process
                print("\n✅ SECURITY CHECK PASSED")
                print("=" * 40)
                print(f"Security Status: {category.upper()}")
                print(f"Action: {action.upper()}")
                print("Proceeding to AI processing...")
                print("=" * 40)

                # ╔══════════════════════════════════════════════════════════════════════════╗
                # ║                        🤖 CLAUDE AI PROCESSING                          ║
                # ║                                                                          ║
                # ║ 🧠 CHATBOT COMPONENT: This is where the AI magic happens!              ║
                # ║                                                                          ║
                # ║ What's happening: Your message passed Palo Alto's security screening   ║
                # ║ and has been approved as safe. NOW we can finally send it to           ║
                # ║ Claude AI to get an intelligent response.                              ║
                # ║                                                                          ║
                # ║ Key Security Note: Only messages that Palo Alto approved ever          ║
                # ║ reach this point. Dangerous messages are blocked above and never       ║
                # ║ make it to the AI processing.                                           ║
                # ║                                                                          ║
                # ║ Flow: Security Approved ✅ → Send to Claude → Get Smart Response       ║
                # ╚══════════════════════════════════════════════════════════════════════════╝
                if claude_client:
                    print("\n🧠 AI PROCESSING PHASE")
                    print("=" * 50)
                    print("Generating Claude response...")

                    try:
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # 🚀 SEND APPROVED MESSAGE TO CLAUDE AI
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # This is where we finally send your security-approved message to 
                        # Claude AI. Claude will analyze your request and generate an
                        # intelligent, thoughtful response using advanced reasoning.
                        response = claude_client.messages.create(
                            model=CLAUDE_MODEL,  # 🧠 Claude model ID, defaults to claude-sonnet-5-5
                            max_tokens=800,      # 📏 Maximum length of AI response
                            # No temperature: the anthropic SDK dropped the
                            # parameter in 2.x and raises TypeError if passed.
                            messages=[
                                {
                                    "role": "user",           # 👤 This identifies the message as coming from a user
                                    "content": user_input     # 💬 Your actual (security-approved) message
                                }
                            ]
                        )

                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # 📤 EXTRACT AND DISPLAY CLAUDE'S AI RESPONSE
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # Claude sends back a complex response object. We need to extract
                        # just the actual text response that the user wants to see.
                        ai_response = "".join(
                            block.text for block in response.content if getattr(block, "type", "") == "text")

                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # 🛡️ SCAN THE RESPONSE BEFORE SHOWING IT
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # The model's output goes back to Palo Alto together with the
                        # prompt. This is where leaked sensitive data, malicious URLs or
                        # code, toxic content, and dangerous SQL in the reply get caught.
                        print("\n🔒 RESPONSE SCANNING PHASE")
                        print("=" * 50)
                        response_scan = scan_prompt_with_paloalto_api(
                            user_input, pan_api_key, pan_ai_profile_name,
                            response=ai_response)

                        if response_scan is None:
                            # Fail closed: if we cannot scan the reply, do not show it.
                            print("\n❌ RESPONSE SCAN FAILED")
                            print("🤖 Response: The AI reply could not be security scanned,")
                            print("   so it was not displayed. Please try again.")
                        elif response_scan.get("category") == "malicious" or response_scan.get("action") == "block":
                            print("\n🚫 AI RESPONSE BLOCKED BY SECURITY")
                            print("=" * 40)
                            print(f"Security Status: {str(response_scan.get('category')).upper()}")
                            print(f"Action Taken: {str(response_scan.get('action')).upper()}")
                            print("\n🤖 Response: The AI generated a reply that violates the")
                            print("   security profile, so it was withheld.")
                            print("=" * 40)
                        else:
                            # 🎉 SUCCESS! Display the final AI response to the user
                            # At this point, your message has been:
                            # 1. ✅ Security scanned by Palo Alto (prompt passed)
                            # 2. 🧠 Processed by Claude AI (intelligent response generated)
                            # 3. ✅ Security scanned by Palo Alto again (response passed)
                            # 4. 📤 Delivered back to you safely
                            print("\n" + "=" * 60)
                            print("🤖 CLAUDE RESPONSE:")
                            print("=" * 60)
                            print(ai_response)
                            print("=" * 60)

                    except Exception as claude_err:
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # ❌ HANDLE CLAUDE AI ERRORS
                        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        # If something goes wrong with Claude AI (server down, quota exceeded,
                        # API changes), we handle it gracefully and inform the user.
                        print(f"\n❌ CLAUDE ERROR: {claude_err}")
                        print("🤖 Response: A technical error occurred during")
                        print("   AI processing. Please try again later.")

                else:
                    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    # ⚠️ CLAUDE AI NOT AVAILABLE
                    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    # This happens if Claude AI couldn't be initialized (wrong API key,
                    # service down, etc.). The security scanning still worked, but we can't
                    # generate AI responses.
                    print("\n⚠️  CLAUDE UNAVAILABLE")
                    print("🤖 Response: Your message passed security screening,")
                    print("   but AI processing is currently unavailable due to")
                    print("   configuration issues.")

            else:
                # UNEXPECTED SECURITY RESULT
                print(f"\n⚠️  UNEXPECTED SECURITY RESULT")
                print(f"   Category: {category}")
                print(f"   Action: {action}")
                print("🤖 Response: Received an unexpected security assessment.")
                print("   Please verify your Palo Alto Networks configuration.")

        else:
            # SECURITY SCAN FAILURE
            print("\n❌ SECURITY SCAN FAILED")
            print("🤖 Response: Unable to complete security scanning.")
            print("   Please check your Palo Alto Networks API configuration")
            print("   and network connectivity.")


# PROGRAM ENTRY POINT
if __name__ == "__main__":
    """
    Program execution starts here when script is run directly.

    This conditional ensures main() only runs when this file is executed
    directly, not when imported as a module by other Python scripts.
    """
    main()