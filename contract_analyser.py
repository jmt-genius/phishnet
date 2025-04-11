import os
import json
import requests
import tempfile
import tiktoken
import google.generativeai as genai
from typing import List, Dict, Optional, Tuple
from dotenv import load_dotenv
from slither.slither import Slither
from slither.exceptions import SlitherError

load_dotenv()  # Load variables from .env

# Configure API keys
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Network configurations
ETHERSCAN_API_URLS = {
    "mainnet": "https://api.etherscan.io/api",
    "sepolia": "https://api-sepolia.etherscan.io/api",
    "goerli": "https://api-goerli.etherscan.io/api",
    "holesky": "https://api-holesky.etherscan.io/api",
}

def check_api_keys() -> Tuple[bool, str]:
    """Check if required API keys are set."""
    missing_keys = []
    
    if not ETHERSCAN_API_KEY:
        missing_keys.append("ETHERSCAN_API_KEY")
    if not GEMINI_API_KEY:
        missing_keys.append("GEMINI_API_KEY")
    
    if missing_keys:
        return False, f"Missing required API keys: {', '.join(missing_keys)}"
    
    return True, "All API keys are set"

def fetch_contract_source(address: str, network: str = "mainnet") -> Dict:
    """Fetch contract source code from Etherscan."""
    url = ETHERSCAN_API_URLS.get(network)
    if not url:
        raise ValueError(f"Unsupported network: {network}")
    
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if data["status"] != "1" or not data["result"]:
            raise ValueError(f"Unable to fetch source code for contract {address} on {network}")
        
        contract_info = data["result"][0]
        if not contract_info or contract_info.get("SourceCode") == "":
            raise Exception(f"Source code not available or not verified for address {address} on {network}")
        
        return {
            "contract_name": contract_info.get("ContractName", f"Contract_{address[-6:]}"),
            "source_code": contract_info["SourceCode"],
            "compiler_version": contract_info.get("CompilerVersion", "")
        }
    except requests.exceptions.RequestException as e:
        raise Exception(f"API request failed: {str(e)}")

def handle_unverified_contract(address: str, network: str) -> Dict:
    """Handle unverified contracts by providing basic information."""
    url = ETHERSCAN_API_URLS.get(network)
    if not url:
        raise ValueError(f"Unsupported network: {network}")
    
    # Get basic contract info
    code_params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": address,
        "tag": "latest",
        "apikey": ETHERSCAN_API_KEY
    }
    
    try:
        code_response = requests.get(url, params=code_params, timeout=30)
        code_data = code_response.json()
        
        # Check if it's a contract
        if code_data.get("result") == "0x":
            raise Exception(f"Address {address} is not a contract.")
        # Get contract creation transaction
        tx_params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": "0",
            "endblock": "99999999",
            "page": "1",
            "offset": "1",
            "sort": "asc",
            "apikey": ETHERSCAN_API_KEY
        }
        
        tx_response = requests.get(url, params=tx_params, timeout=30)
        tx_data = tx_response.json()
        
        creator = "Unknown"
        creation_date = "Unknown"
        
        if tx_data.get("status") == "1" and tx_data.get("result"):
            first_tx = tx_data["result"][0]
            if first_tx.get("to") == "" or first_tx.get("to") == "0x":  # Creation transaction
                creator = first_tx.get("from", "Unknown")
                creation_date = first_tx.get("timeStamp", "Unknown")
        
        return {
            "contract_name": f"UnverifiedContract_{address[-6:]}",
            "source_code": "// Source code not verified",
            "compiler_version": "Unknown",
            "unverified": True,
            "creator": creator,
            "creation_date": creation_date,
            "bytecode_size": len(code_data["result"]) // 2 - 1  # Convert hex to bytes
        }
    except requests.exceptions.RequestException as e:
        raise Exception(f"API request failed: {str(e)}")

def save_source_code(contract_data: Dict, output_dir: str = None) -> str:
    """Save contract source code to files."""
    if not output_dir:
        temp_dir = tempfile.mkdtemp()
    else:
        temp_dir = output_dir
        os.makedirs(temp_dir, exist_ok=True)
    
    source_code = contract_data["source_code"]
    contract_name = contract_data["contract_name"]
    
    # Handle unverified contracts
    if contract_data.get("unverified", False):
        with open(os.path.join(temp_dir, f"{contract_name}.sol"), "w") as f:
            f.write(source_code)
        return temp_dir
    
    # Handle multi-file contracts (JSON format)
    if source_code.strip().startswith("{") and source_code.strip().endswith("}"):
        try:
            # Remove curly braces if present (some Etherscan responses are wrapped)
            if source_code.strip().startswith("{") and source_code.strip().endswith("}"):
                try:
                    source_code_json = json.loads(source_code)
                    
                    # Handle different JSON structures from Etherscan
                    if "sources" in source_code_json:
                        # Standard JSON input format
                        sources = source_code_json.get("sources", {})
                        for path, meta in sources.items():
                            full_path = os.path.join(temp_dir, path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            with open(full_path, "w") as f:
                                content = meta["content"] if isinstance(meta, dict) else meta
                                f.write(content)
                    else:
                        # Direct mapping of files to content
                        for file_path, content in source_code_json.items():
                            full_path = os.path.join(temp_dir, file_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            file_content = content.get("content", content) if isinstance(content, dict) else content
                            with open(full_path, "w") as f:
                                f.write(file_content)
                except json.JSONDecodeError:
                    # Fallback if JSON parsing fails
                    with open(os.path.join(temp_dir, f"{contract_name}.sol"), "w") as f:
                        f.write(source_code)
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            with open(os.path.join(temp_dir, f"{contract_name}.sol"), "w") as f:
                f.write(source_code)
    else:
        # Single file contract
        with open(os.path.join(temp_dir, f"{contract_name}.sol"), "w") as f:
            f.write(source_code)
    
    print(f"[+] Saved source to: {temp_dir}")
    return temp_dir

def extract_functions(temp_dir: str) -> List[Dict]:
    """Extract functions from contract using Slither with proper solc version handling."""
    import re
    import subprocess
    
    # Check if temp_dir contains any Solidity files
    solidity_files = []
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.sol'):
                file_path = os.path.join(root, file)
                solidity_files.append(file_path)
    
    if not solidity_files:
        raise Exception(f"No Solidity files found in {temp_dir}")
    
    # Try to detect Solidity version from pragma statement
    solc_version = None
    main_file = None
    
    for file_path in solidity_files:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            try:
                content = f.read()
                pragma_match = re.search(r'pragma solidity ([^;]+);', content)
                if pragma_match:
                    version_str = pragma_match.group(1).strip()
                    # Handle version ranges
                    if '>=' in version_str:
                        # For ranges like ">=0.7.0 <0.9.0", take the minimum version
                        solc_version = version_str.split('>=')[1].split(' ')[0].strip()
                    elif '^' in version_str:
                        # For caret ranges like "^0.7.0", take the specified version
                        solc_version = version_str.replace('^', '').strip()
                    else:
                        # For exact versions like "0.7.5"
                        solc_version = version_str
                    
                    # Prefer files that might be the main contract (containing contract name matching the file name)
                    file_base_name = os.path.basename(file_path).replace('.sol', '')
                    if f"contract {file_base_name}" in content or f"contract {file_base_name.capitalize()}" in content:
                        main_file = file_path
                        break
            except UnicodeDecodeError:
                print(f"Warning: Could not read {file_path} due to encoding issues")
                continue
    
    # If no main file identified, use the first one
    if not main_file and solidity_files:
        main_file = solidity_files[0]
    
    if not main_file:
        raise Exception("Could not identify a main Solidity file")
    
    print(f"[+] Using main file: {main_file}")
    
    # Try different methods to analyze the contract
    
    # Method 1: Try using solc-select if available
    try:
        # Check if solc-select is installed
        subprocess.run(["solc-select", "--version"], capture_output=True, check=True)
        
        # If we have a detected version, try to use it with solc-select
        if solc_version:
            try:
                print(f"[+] Trying to install solc {solc_version} using solc-select...")
                subprocess.run(["solc-select", "install", solc_version], capture_output=True)
                subprocess.run(["solc-select", "use", solc_version], capture_output=True)
                print(f"[+] Successfully switched to solc {solc_version}")
                
                # Now try Slither with the right version
                slither = Slither(main_file)
                print(f"[✓] Success with solc {solc_version}")
                
                # Process functions and return
                return process_slither_results(slither)
            except Exception as e:
                print(f"[-] Failed with solc {solc_version}: {str(e)}")
    except Exception as e:
        print(f"[-] solc-select not available: {str(e)}")
    
    # Method 2: Try with crytic-compile to handle multiple versions
    try:
        from crytic_compile import CryticCompile
        print("[+] Trying with crytic-compile...")
        
        compilation = CryticCompile(main_file)
        slither = Slither(main_file, compilation)
        print(f"[✓] Success with crytic-compile")
        
        # Process functions and return
        return process_slither_results(slither)
    except Exception as e:
        print(f"[-] Failed with crytic-compile: {str(e)}")
    
    # Method 3: Use manual override to disable version check
    try:
        # Create a temporary copy of the contract with modified pragma
        temp_file = f"{main_file}.temp.sol"
        with open(main_file, 'r', encoding='utf-8', errors='replace') as src, open(temp_file, 'w') as dst:
            content = src.read()
            # Replace strict pragma with a more flexible one
            content = re.sub(r'pragma solidity [^;]+;', 'pragma solidity ^0.7.0;', content)
            dst.write(content)
        
        print("[+] Trying with modified pragma...")
        slither = Slither(temp_file)
        print(f"[✓] Success with modified pragma")
        
        # Process functions and return
        result = process_slither_results(slither)
        
        # Clean up temporary file
        os.remove(temp_file)
        
        return result
    except Exception as e:
        print(f"[-] Failed with modified pragma: {str(e)}")
        # Try to clean up temporary file if it exists
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass
    
    # If all methods fail, fall back to manual extraction
    print("[+] All Slither methods failed, falling back to manual extraction...")
    return manual_extract_functions(temp_dir)

def process_slither_results(slither):
    """Process results from a successful Slither analysis."""
    all_funcs = []
    for contract in slither.contracts:
        for func in contract.functions:
            # Skip very short or constructor functions
            if func.name == 'constructor' or len(func.source_mapping.content) < 10:
                continue
                
            all_funcs.append({
                "contract": contract.name,
                "name": func.name,
                "visibility": func.visibility,
                "modifiers": [m.name for m in func.modifiers],
                "parameters": [str(p.type) for p in func.parameters],
                "returns": [str(r.type) for r in func.returns],
                "state_mutability": func.state_mutability,
                "source": func.source_mapping.content
            })
    
    print(f"[+] Extracted {len(all_funcs)} functions.")
    return all_funcs

def manual_extract_functions(temp_dir: str) -> List[Dict]:
    """Extract functions manually from Solidity files when Slither fails."""
    import re
    
    function_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(public|private|internal|external)?(?:\s+(view|pure|payable))?\s*(?:returns\s*\(([^)]*)\))?\s*{([^}]*)}'
    
    all_funcs = []
    
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.sol'):
                file_path = os.path.join(root, file)
                contract_name = os.path.basename(file_path).replace('.sol', '')
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                        
                        # Extract contract names
                        contract_matches = re.finditer(r'contract\s+(\w+)', content)
                        contracts = [match.group(1) for match in contract_matches]
                        
                        if contracts:
                            contract_name = contracts[0]  # Use first contract name found
                        
                        # Find all functions
                        for match in re.finditer(function_pattern, content, re.DOTALL):
                            name = match.group(1)
                            params = match.group(2).strip()
                            visibility = match.group(3) or "public"
                            mutability = match.group(4) or "nonpayable"
                            returns = match.group(5) or ""
                            body = match.group(6)
                            
                            # Extract parameters as a list
                            param_list = []
                            if params:
                                for param in params.split(','):
                                    param = param.strip()
                                    if param:
                                        parts = param.split()
                                        if len(parts) >= 1:
                                            param_list.append(parts[0])  # Just get the type
                            
                            # Extract return types as a list
                            return_list = []
                            if returns:
                                for ret in returns.split(','):
                                    ret = ret.strip()
                                    if ret:
                                        parts = ret.split()
                                        if len(parts) >= 1:
                                            return_list.append(parts[0])  # Just get the type
                            
                            # Construct source code
                            source_code = f"function {name}({params}) {visibility}"
                            if mutability != "nonpayable":
                                source_code += f" {mutability}"
                            if returns:
                                source_code += f" returns ({returns})"
                            source_code += " { ... }"
                            
                            all_funcs.append({
                                "contract": contract_name,
                                "name": name,
                                "visibility": visibility,
                                "modifiers": [],  # Can't extract reliably without parser
                                "parameters": param_list,
                                "returns": return_list,
                                "state_mutability": mutability,
                                "source": source_code
                            })
                except Exception as e:
                    print(f"[-] Error parsing {file_path}: {str(e)}")
                    continue
    
    print(f"[+] Manually extracted {len(all_funcs)} functions.")
    return all_funcs

def chunk_code(functions: List[Dict], max_tokens: int = 6000) -> List[List[Dict]]:
    """Split functions into chunks that fit within token limits."""
    if not functions:
        return []
        
    chunks = []
    current_chunk = []
    estimated_tokens = 0
    
    # Rough approximation: 1 token ≈ 4 characters
    chars_per_token = 4
    
    for func in functions:
        func_json = json.dumps(func, indent=2)
        estimated_func_tokens = len(func_json) // chars_per_token
        
        if estimated_tokens + estimated_func_tokens > max_tokens and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            estimated_tokens = 0
        
        current_chunk.append(func)
        estimated_tokens += estimated_func_tokens
    
    if current_chunk:
        chunks.append(current_chunk)
    
    print(f"[+] Split into {len(chunks)} chunk(s).")
    return chunks

def build_prompt(chunk: List[Dict]) -> str:
    """Build a prompt for the Gemini model to analyze."""
    prompt = "You are a Solidity smart contract security expert. Analyze the following functions and report vulnerabilities and risks as a Markdown list. Focus on:\n"
    prompt += "- Reentrancy vulnerabilities\n"
    prompt += "- Overflow/underflow issues\n"
    prompt += "- Access control problems\n"
    prompt += "- Logic errors\n"
    prompt += "- External contract dependencies\n"
    prompt += "- Gas optimization issues\n\n"
    
    for func in chunk:
        prompt += f"\n### Contract: {func['contract']} | Function: `{func['name']}`\n"
        prompt += f"- **Visibility**: {func['visibility']}\n"
        prompt += f"- **Mutability**: {func['state_mutability']}\n"
        prompt += f"- **Modifiers**: {', '.join(func['modifiers']) or 'None'}\n"
        prompt += f"- **Parameters**: {', '.join(func['parameters'])}\n"
        prompt += f"- **Returns**: {', '.join(func['returns']) if func['returns'] else 'None'}\n"
        prompt += f"\n```solidity\n{func['source']}\n```\n"
    
    return prompt

def analyze_chunks_with_gemini(chunks: List[List[Dict]]) -> List[Dict]:
    """Analyze code chunks using Google's Gemini model."""
    if not chunks:
        return [{"chunk": 1, "analysis": "No code to analyze."}]
        
    print("🔑 Configuring Gemini...")
    genai.configure(api_key=GEMINI_API_KEY)
    
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
    except Exception as e:
        print(f"❌ Failed to initialize Gemini model: {str(e)}")
        return [{"chunk": 1, "analysis": f"Failed to initialize Gemini model: {str(e)}"}]
    
    results = []
    for idx, chunk in enumerate(chunks):
        print(f"🧠 Analyzing chunk {idx+1}/{len(chunks)}...")
        prompt = build_prompt(chunk)
        
        try:
            response = model.generate_content(prompt)
            results.append({"chunk": idx+1, "analysis": response.text})
        except Exception as e:
            print(f"❌ Gemini failed on chunk {idx+1}: {str(e)}")
            results.append({"chunk": idx+1, "analysis": f"Gemini analysis failed: {str(e)}"})
    
    return results

def generate_security_report(analysis_results: List[Dict], contract_name: str, network: str) -> Dict:
    """Generate a comprehensive security report from analysis results."""
    if not analysis_results or all(not result.get("analysis") for result in analysis_results):
        return {
            "contract_name": contract_name,
            "network": network,
            "overall_risk": "Unknown",
            "safety_status": "Could not analyze",
            "issues_count": {"high": 0, "medium": 0, "low": 0, "total": 0},
            "issues": []
        }
        
    analysis_texts = [result.get("analysis", "") for result in analysis_results]
    
    # Extract severity data
    severity_keywords = {
        "high": ["critical", "high risk", "severe", "reentrancy", "race condition", "fund loss", "theft", 
                 "unauthorized access", "overflow", "underflow", "arbitrary code execution"],
        "medium": ["medium risk", "centralization", "censorship", "manipulation", "front-running", 
                  "timestamp dependence", "gas limit", "denial of service"],
        "low": ["low risk", "minor", "gas inefficiency", "naming convention", "documentation"]
    }
    
    severity_count = {"high": 0, "medium": 0, "low": 0}
    found_issues = []
    
    for text in analysis_texts:
        if not text:
            continue
            
        # Extract issues by looking for bullet points or numbered lists
        import re
        issues = re.findall(r'[-*•]\s*(.*?)(?=\n[-*•]|\n\n|\n#|\Z)', text, re.DOTALL)
        issues.extend(re.findall(r'\d+\.\s*(.*?)(?=\n\d+\.|\n\n|\n#|\Z)', text, re.DOTALL))
        
        for issue in issues:
            issue = issue.strip()
            if not issue or len(issue) < 10:  # Skip very short items
                continue
                
            # Determine severity
            severity = "low"  # Default
            for level, keywords in severity_keywords.items():
                if any(keyword.lower() in issue.lower() for keyword in keywords):
                    severity = level
                    break
                    
            severity_count[severity] += 1
            found_issues.append({"severity": severity, "description": issue})
    
    # Sort issues by severity
    found_issues.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}[x["severity"]])
    
    # Get overall assessment
    overall_assessment = "Low"
    if severity_count["high"] > 0:
        overall_assessment = "High"
    elif severity_count["medium"] > 0:
        overall_assessment = "Medium"
    
    # Determine if contract is safe
    safe_status = "Not Safe" if overall_assessment == "High" else "Exercise Caution" if overall_assessment == "Medium" else "Likely Safe"
    
    return {
        "contract_name": contract_name,
        "network": network,
        "overall_risk": overall_assessment,
        "safety_status": safe_status,
        "issues_count": {
            "high": severity_count["high"],
            "medium": severity_count["medium"],
            "low": severity_count["low"],
            "total": sum(severity_count.values())
        },
        "issues": found_issues[:10]  # Top 10 issues
    }

def format_report_as_markdown(report: Dict) -> str:
    """Format the security report as Markdown."""
    import datetime
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    
    md = f"""# Smart Contract Security Assessment

## Contract Information
- **Contract Name:** {report['contract_name']}
- **Network:** {report['network'].capitalize()}
- **Analysis Date:** {current_date}

## Risk Assessment
- **Overall Risk Level:** {report['overall_risk']}
- **Contract Status:** {report['safety_status']}
- **Issues Found:** {report['issues_count']['total']} ({report['issues_count']['high']} high, {report['issues_count']['medium']} medium, {report['issues_count']['low']} low)

## Key Issues

"""
    
    # Add issues grouped by severity
    for severity in ["high", "medium", "low"]:
        severity_issues = [issue for issue in report['issues'] if issue['severity'] == severity]
        if severity_issues:
            md += f"### {severity.capitalize()} Severity Issues\n\n"
            for i, issue in enumerate(severity_issues, 1):
                md += f"{i}. {issue['description']}\n\n"
    
    # Add recommendation
    md += "## Recommendation\n\n"
    if report['overall_risk'] == "High":
        md += "**DO NOT INTERACT** with this contract without addressing the critical security issues identified above. The contract has significant vulnerabilities that could lead to loss of funds or other severe consequences.\n\n"
    elif report['overall_risk'] == "Medium":
        md += "**EXERCISE CAUTION** when interacting with this contract. Address the identified issues before deploying in production or investing significant funds.\n\n"
    else:
        md += "The contract appears to have minimal security concerns, but we recommend addressing the identified issues for best practices.\n\n"
    
    md += "## Disclaimer\n\n"
    md += "This assessment is based on automated analysis and may not catch all potential vulnerabilities. We recommend a comprehensive manual audit before deploying critical contracts.\n"
    
    return md

def generate_unverified_report(contract_data: Dict, address: str, network: str) -> str:
    """Generate a basic report for unverified contracts."""
    import datetime
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    
    creation_date = contract_data.get("creation_date", "Unknown")
    if creation_date != "Unknown" and creation_date.isdigit():
        try:
            # Convert Unix timestamp to readable date
            from datetime import datetime
            creation_date = datetime.fromtimestamp(int(creation_date)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
    
    md = f"""# Unverified Contract Analysis

## Warning
This contract has not been verified on {network}. Analysis is limited and based on bytecode only.

## Contract Information
- **Address:** {address}
- **Network:** {network.capitalize()}
- **Analysis Date:** {current_date}
- **Creator:** {contract_data.get("creator", "Unknown")}
- **Creation Date:** {creation_date}
- **Bytecode Size:** {contract_data.get("bytecode_size", "Unknown")} bytes

## Risk Assessment
- **Risk Level:** Unknown (Unverified Contract)
- **Status:** Potentially Unsafe

## Recommendations

1. **USE EXTREME CAUTION** when interacting with unverified contracts.
2. Unverified contracts cannot be audited for security vulnerabilities.
3. Consider the following potential risks:
   - The contract may contain backdoors or malicious code
   - Funds sent to the contract might be locked or stolen
   - The contract might not function as advertised

## Next Steps

1. **Contact the contract developer** to request verification on Etherscan
2. Consider using a bytecode analyzer tool for deeper inspection
3. Check for similar patterns in known malicious contracts
4. Look for any public discussions or reviews of this contract

## Disclaimer

This assessment is based on limited information. Interacting with unverified contracts carries significant risk.
"""
    
    return md

def detect_network(address: str) -> str:
    """Determine which network an address is active on."""
    networks = ["mainnet", "sepolia", "goerli", "holesky"]
    contract_candidates = []
    balance_candidates = []

    for network in networks:
        try:
            url = ETHERSCAN_API_URLS[network]
            print(f"[~] Checking network: {network}")

            # Check for contract code
            code_params = {
                "module": "proxy",
                "action": "eth_getCode",
                "address": address,
                "tag": "latest",
                "apikey": ETHERSCAN_API_KEY
            }
            code_response = requests.get(url, params=code_params, timeout=10)
            code_data = code_response.json()
            code_result = code_data.get("result", "")

            if code_result and code_result != "0x":
                print(f"[✓] Detected contract code on {network}")
                return network  # Prioritize contract presence
            else:
                print(f"[-] No contract code on {network}")

            # Check transaction count
            tx_params = {
                "module": "proxy",
                "action": "eth_getTransactionCount",
                "address": address,
                "tag": "latest",
                "apikey": ETHERSCAN_API_KEY
            }
            tx_response = requests.get(url, params=tx_params, timeout=10)
            tx_data = tx_response.json()
            txn_count = int(tx_data.get("result", "0x0"), 16)
            if txn_count > 0:
                print(f"[~] Detected {txn_count} transactions on {network}")
                contract_candidates.append((network, txn_count))

            # Check balance
            balance_params = {
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
                "apikey": ETHERSCAN_API_KEY
            }
            balance_response = requests.get(url, params=balance_params, timeout=10)
            balance_data = balance_response.json()
            balance = int(balance_data.get("result", "0"))
            if balance > 0:
                print(f"[~] Detected balance on {network}: {balance}")
                balance_candidates.append((network, balance))

        except Exception as e:
            print(f"[!] Error checking {network}: {e}")

    # If no contract found, use fallback heuristics
    if contract_candidates:
        network = contract_candidates[0][0]
        print(f"[+] Fallback: using transaction history, choosing {network}")
        return network
    elif balance_candidates:
        network = balance_candidates[0][0]
        print(f"[+] Fallback: using balance, choosing {network}")
        return network

    print("[!] Could not determine network. Defaulting to mainnet.")
    return "mainnet"




def main(address: str, network: str = None, output_dir: str = "output"):
    """Main function to analyze a smart contract."""
    # Check API keys
    keys_ok, message = check_api_keys()
    if not keys_ok:
        print(f"[!] {message}")
        return None
        
    if network is None:
        print("[*] No network specified, attempting to auto-detect...")
        network = detect_network(address)
        print(f"[+] Auto-detected network: {network}")


    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    network_dir = os.path.join(output_dir, network)
    os.makedirs(network_dir, exist_ok=True)
    
    try:
        # Step 1: Fetch contract source from Etherscan
        print(f"[+] Fetching contract {address} from {network}...")
        try:
            contract_data = fetch_contract_source(address, network)
            is_unverified = False
        except Exception as e:
            print(f"[!] Error fetching verified source: {str(e)}")
            print("[+] Attempting to gather basic info for unverified contract...")
            contract_data = handle_unverified_contract(address, network)
            is_unverified = True
        
        # Step 2: Save source code to files
        contract_dir = os.path.join(network_dir, "contracts")
        temp_dir = save_source_code(contract_data, contract_dir)
        
        # For unverified contracts, generate a basic report and exit
        if is_unverified:
            print("[!] Contract is not verified. Generating basic report...")
            unverified_report = generate_unverified_report(contract_data, address, network)
            report_path = os.path.join(network_dir, "unverified_report.md")
            with open(report_path, "w") as f:
                f.write(unverified_report)
            print(f"[✓] Unverified contract report written to {report_path}")
            return {
                "contract_name": contract_data.get("contract_name", f"UnverifiedContract_{address[-6:]}"),
                "report_path": report_path,
                "network": network,
                "risk_level": "Unknown",
                "status": "Potentially Unsafe",
                "unverified": True
            }
        
        # Step 3: Extract functions using Slither or fallback to manual extraction
        try:
            functions = extract_functions(temp_dir)
        except Exception as e:
            print(f"[!] Slither analysis failed: {str(e)}")
            print("[+] Falling back to manual function extraction...")
            functions = manual_extract_functions(temp_dir)
        
        if not functions:
            print("[!] No functions could be extracted from the contract")
            return None
            
        # Save functions to JSON for reference
        with open(os.path.join(network_dir, "functions.json"), "w") as f:
            json.dump(functions, f, indent=2)
        
        # Step 4: Split functions into chunks for analysis
        chunks = chunk_code(functions)
        
        # Save chunks for reference
        for i, chunk in enumerate(chunks):
            with open(os.path.join(network_dir, f"chunk_{i+1}.json"), "w") as f:
                json.dump(chunk, f, indent=2)
        
        # Step 5: Analyze chunks with Gemini
        analysis_results = analyze_chunks_with_gemini(chunks)
        
        # Save analysis results
        with open(os.path.join(network_dir, "analysis_results.json"), "w") as f:
            json.dump(analysis_results, f, indent=2)
        
        # Step 6: Generate comprehensive security report
        report = generate_security_report(analysis_results, contract_data["contract_name"], network)
        
        # Save report data
        with open(os.path.join(network_dir, "report_data.json"), "w") as f:
            json.dump(report, f, indent=2)
        
        # Format report as Markdown
        md_report = format_report_as_markdown(report)
        
        # Save Markdown report
        report_path = os.path.join(network_dir, "security_report.md")
        with open(report_path, "w") as f:
            f.write(md_report)
        
        print(f"[✓] Report written to {report_path}")
        print("\nSummary:")
        print(f"- Risk Level: {report['overall_risk']}")
        print(f"- Status: {report['safety_status']}")
        print(f"- Issues: {report['issues_count']['total']} ({report['issues_count']['high']} high, {report['issues_count']['medium']} medium, {report['issues_count']['low']} low)")
        
        return {
            "contract_name": contract_data["contract_name"],
            "report_path": report_path,
            "network": network,
            "risk_level": report["overall_risk"],
            "status": report["safety_status"]
        }
        
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze smart contracts for security vulnerabilities")
    parser.add_argument("--address", required=True, help="Verified contract address")
    parser.add_argument("--network", default=None, choices=list(ETHERSCAN_API_URLS.keys()) + [None], 
                        help="Ethereum network (default: auto-detect)")
    parser.add_argument("--output", default="output", help="Output directory (default: output)")
    parser.add_argument("--etherscan-key", dest="etherscan_key", 
                        help="Etherscan API key (or set ETHERSCAN_API_KEY env variable)")
    parser.add_argument("--gemini-key", dest="gemini_key",
                        help="Google Gemini API key (or set GEMINI_API_KEY env variable)")
    
    args = parser.parse_args()
    
    # Override environment variables if provided
    if args.etherscan_key:
        ETHERSCAN_API_KEY = args.etherscan_key
    if args.gemini_key:
        GEMINI_API_KEY = args.gemini_key
    
    result = main(args.address, args.network, args.output)
    
    if result:
        print("\n✅ Analysis complete!")