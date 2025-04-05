import os
import json
import google.generativeai as genai
from typing import List, Dict

# Step 1: Fetch contract source from Etherscan
def fetch_contract_source(address: str, api_key: str) -> dict:
    import requests
    base_url = "https://api.etherscan.io/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key
    }
    response = requests.get(base_url, params=params)
    data = response.json()
    if data["status"] != "1" or not data["result"]:
        raise ValueError(f"Error fetching contract: {data['message']}")
    result = data["result"][0]
    return {
        "source_code": result["SourceCode"],
        "contract_name": result["ContractName"],
        "compiler_version": result["CompilerVersion"]
    }

# Step 2: Save contract files
def save_contract_files(contract_name, source_code_raw, output_dir="contracts"):
    os.makedirs(output_dir, exist_ok=True)
    try:
        source_code_json = json.loads(source_code_raw.strip().lstrip('{').rstrip('}'))
        if isinstance(source_code_json, dict):
            for file_path, file_content in source_code_json.items():
                content = file_content.get("content", file_content)
                full_path = os.path.join(output_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w") as f:
                    f.write(content)
            return os.path.join(output_dir, contract_name + ".sol")
        else:
            raise ValueError("Unrecognized multi-file contract format.")
    except json.JSONDecodeError:
        filename = os.path.join(output_dir, f"{contract_name}.sol")
        with open(filename, "w") as f:
            f.write(source_code_raw)
        return filename

# Step 3: Extract functions using Slither
def extract_functions_with_slither(contract_path):
    from slither.slither import Slither
    slither = Slither(contract_path)
    functions = []
    for contract in slither.contracts:
        for function in contract.functions:
            functions.append({
                "contract": contract.name,
                "name": function.name,
                "modifiers": [str(m.name) for m in function.modifiers],
                "parameters": [str(p.type) for p in function.parameters],
                "returns": [str(r.type) for r in function.returns],
                "visibility": function.visibility,
                "state_mutability": getattr(function, "state_mutability", "unknown"),
                "source": function.source_mapping.content
            })
    return functions

def chunk_functions(functions: List[Dict], max_tokens: int = 6000):
    import tiktoken
    def estimate_tokens(text: str) -> int:
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    chunks = []
    current_chunk = []
    current_token_count = 0
    for func in functions:
        func_text = json.dumps(func, indent=2)
        func_tokens = estimate_tokens(func_text)
        if current_token_count + func_tokens > max_tokens:
            chunks.append(current_chunk)
            current_chunk = []
            current_token_count = 0
        current_chunk.append(func)
        current_token_count += func_tokens
    if current_chunk:
        chunks.append(current_chunk)
    return chunks

def analyze_with_gemini(chunks, api_key):
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-001")
    results = []
    for i, chunk in enumerate(chunks):
        prompt = f"""
        Analyze the following Solidity functions for security risks:
        {json.dumps(chunk, indent=2)}
        """
        response = model.generate_content(prompt)
        results.append({"chunk": i+1, "analysis": response.text})
    return results

def generate_function_prompts(functions, contract_name):
    prompts = []
    for fn in functions:
        name = fn["name"]
        params = ", ".join(fn["parameters"])
        visibility = fn.get("visibility", "public")
        modifiers = ", ".join(fn.get("modifiers", []))
        returns = ", ".join(fn.get("returns", [])) if fn.get("returns") else "none"
        state = fn.get("state_mutability", "nonpayable")
        header = f"[Function `{name}` from {contract_name}]"
        sig = f"function {name}({params}) {visibility} {modifiers}".strip()
        if state and state != "nonpayable":
            sig += f" {state}"
        if returns and returns != "none":
            sig += f" returns ({returns})"
        full_source = fn.get("source", "<source unavailable>")
        prompt = f"""{header}{sig}
{full_source}
\nQ: Are there any security vulnerabilities or high-risk patterns in this function? Explain clearly with examples."""
        prompts.append({"function_name": name, "prompt": prompt})
    return prompts

def analyze_smart_contract(contract_address, etherscan_api_key, gemini_api_key, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    contract_data = fetch_contract_source(contract_address, etherscan_api_key)
    contract_path = save_contract_files(contract_data["contract_name"], contract_data["source_code"], os.path.join(output_dir, "contracts"))
    functions = extract_functions_with_slither(contract_path)
    with open(os.path.join(output_dir, "functions.json"), "w") as f:
        json.dump(functions, f, indent=2)
    chunks = chunk_functions(functions)
    for i, chunk in enumerate(chunks):
        with open(os.path.join(output_dir, f"chunk_{i}.json"), "w") as f:
            json.dump(chunk, f, indent=2)
    analysis = analyze_with_gemini(chunks, gemini_api_key)
    with open(os.path.join(output_dir, "analysis.json"), "w") as f:
        json.dump(analysis, f, indent=2)
    prompts = generate_function_prompts(functions, contract_data["contract_name"])
    with open(os.path.join(output_dir, "prompts.jsonl"), "w") as f:
        for p in prompts:
            f.write(json.dumps(p) + "\n")
    return {
        "contract_name": contract_data["contract_name"],
        "contract_path": contract_path,
        "functions_file": os.path.join(output_dir, "functions.json"),
        "analysis_file": os.path.join(output_dir, "analysis.json"),
        "prompts_file": os.path.join(output_dir, "prompts.jsonl")
    }

def generate_security_report(analysis_json_path):
    with open(analysis_json_path, 'r') as f:
        analysis_json = json.load(f)
    analysis_data = [entry["analysis"] for entry in analysis_json]
    num_vulnerabilities = len(analysis_data)
    severity_keywords = {
        "high": ["critical", "reentrancy", "race condition", "fund loss"],
        "medium": ["centralization", "censorship", "manipulation"],
        "low": ["unspecified", "unknown"]
    }
    severity_count = {"high": 0, "medium": 0, "low": 0}
    for entry in analysis_data:
        for severity, keywords in severity_keywords.items():
            if any(keyword in entry.lower() for keyword in keywords):
                severity_count[severity] += 1
    overall_assessment = "High" if severity_count["high"] > 0 else "Medium" if severity_count["medium"] > 0 else "Low"
    top_vulnerabilities = analysis_data[:3]
    safe_address = "Not Safe" if overall_assessment == "High" else "Safe"
    return {
        "num_vulnerabilities": num_vulnerabilities,
        "overall_assessment": overall_assessment,
        "top_vulnerabilities": top_vulnerabilities,
        "safe_address": safe_address
    }

def format_report_for_display(report):
    output = f"""
SMART CONTRACT SECURITY ASSESSMENT

Vulnerabilities Found: {report['num_vulnerabilities']}
Risk Level: {report['overall_assessment']}
Address Status: {report['safe_address']}

TOP ISSUES:
"""
    for i, vuln in enumerate(report['top_vulnerabilities'], 1):
        output += f"{i}. {vuln}\n\n"
    output += """
RECOMMENDATION:
"""
    output += "Do not interact with this contract without addressing the security issues." if report['safe_address'] == "Not Safe" else "Exercise caution when interacting with this contract."
    return output.strip()

import os
import json
import google.generativeai as genai
from typing import List, Dict
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env

# Step 1: Fetch contract source from Etherscan
def fetch_contract_source(address: str, api_key: str) -> dict:
    import requests
    base_url = "https://api.etherscan.io/api"
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key
    }
    response = requests.get(base_url, params=params)
    data = response.json()
    if data["status"] != "1" or not data["result"]:
        raise ValueError(f"Error fetching contract: {data['message']}")
    result = data["result"][0]
    return {
        "source_code": result["SourceCode"],
        "contract_name": result["ContractName"],
        "compiler_version": result["CompilerVersion"]
    }

# Step 2: Save contract files
def save_contract_files(contract_name, source_code_raw, output_dir="contracts"):
    os.makedirs(output_dir, exist_ok=True)
    try:
        source_code_json = json.loads(source_code_raw.strip().lstrip('{').rstrip('}'))
        if isinstance(source_code_json, dict):
            for file_path, file_content in source_code_json.items():
                content = file_content.get("content", file_content)
                full_path = os.path.join(output_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w") as f:
                    f.write(content)
            return os.path.join(output_dir, contract_name + ".sol")
        else:
            raise ValueError("Unrecognized multi-file contract format.")
    except json.JSONDecodeError:
        filename = os.path.join(output_dir, f"{contract_name}.sol")
        with open(filename, "w") as f:
            f.write(source_code_raw)
        return filename

# Step 3: Extract functions using Slither
def extract_functions_with_slither(contract_path):
    from slither.slither import Slither
    slither = Slither(contract_path)
    functions = []
    for contract in slither.contracts:
        for function in contract.functions:
            functions.append({
                "contract": contract.name,
                "name": function.name,
                "modifiers": [str(m.name) for m in function.modifiers],
                "parameters": [str(p.type) for p in function.parameters],
                "returns": [str(r.type) for r in function.returns],
                "visibility": function.visibility,
                "state_mutability": getattr(function, "state_mutability", "unknown"),
                "source": function.source_mapping.content
            })
    return functions

def chunk_functions(functions: List[Dict], max_tokens: int = 6000):
    import tiktoken
    def estimate_tokens(text: str) -> int:
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    chunks = []
    current_chunk = []
    current_token_count = 0
    for func in functions:
        func_text = json.dumps(func, indent=2)
        func_tokens = estimate_tokens(func_text)
        if current_token_count + func_tokens > max_tokens:
            chunks.append(current_chunk)
            current_chunk = []
            current_token_count = 0
        current_chunk.append(func)
        current_token_count += func_tokens
    if current_chunk:
        chunks.append(current_chunk)
    return chunks

def analyze_with_gemini(chunks, api_key):
    print("🔑 Configuring Gemini...")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash-001")
    results = []
    for i, chunk in enumerate(chunks):
        print(f"🧠 Analyzing chunk {i + 1}...")
        prompt = f"""
        Analyze the following Solidity functions for security risks:
        {json.dumps(chunk, indent=2)}
        """
        try:
            response = model.generate_content(prompt)
            results.append({"chunk": i+1, "analysis": response.text})
        except Exception as e:
            print(f"❌ Gemini failed on chunk {i+1}: {e}")
            results.append({"chunk": i+1, "analysis": "Gemini analysis failed."})
    return results

def generate_function_prompts(functions, contract_name):
    prompts = []
    for fn in functions:
        name = fn["name"]
        params = ", ".join(fn["parameters"])
        visibility = fn.get("visibility", "public")
        modifiers = ", ".join(fn.get("modifiers", []))
        returns = ", ".join(fn.get("returns", [])) if fn.get("returns") else "none"
        state = fn.get("state_mutability", "nonpayable")
        header = f"[Function `{name}` from {contract_name}]"
        sig = f"function {name}({params}) {visibility} {modifiers}".strip()
        if state and state != "nonpayable":
            sig += f" {state}"
        if returns and returns != "none":
            sig += f" returns ({returns})"
        full_source = fn.get("source", "<source unavailable>")
        prompt = f"""{header}{sig}
{full_source}
\nQ: Are there any security vulnerabilities or high-risk patterns in this function? Explain clearly with examples."""
        prompts.append({"function_name": name, "prompt": prompt})
    return prompts

def analyze_smart_contract(contract_address, etherscan_api_key, gemini_api_key, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    print(f"🚀 Analyzing contract: {contract_address}")
    contract_data = fetch_contract_source(contract_address, etherscan_api_key)
    contract_path = save_contract_files(contract_data["contract_name"], contract_data["source_code"], os.path.join(output_dir, "contracts"))
    functions = extract_functions_with_slither(contract_path)
    with open(os.path.join(output_dir, "functions.json"), "w") as f:
        json.dump(functions, f, indent=2)
    chunks = chunk_functions(functions)
    for i, chunk in enumerate(chunks):
        with open(os.path.join(output_dir, f"chunk_{i}.json"), "w") as f:
            json.dump(chunk, f, indent=2)
    analysis = analyze_with_gemini(chunks, gemini_api_key)
    with open(os.path.join(output_dir, "analysis.json"), "w") as f:
        json.dump(analysis, f, indent=2)
    prompts = generate_function_prompts(functions, contract_data["contract_name"])
    with open(os.path.join(output_dir, "prompts.jsonl"), "w") as f:
        for p in prompts:
            f.write(json.dumps(p) + "\n")
    return {
        "contract_name": contract_data["contract_name"],
        "contract_path": contract_path,
        "functions_file": os.path.join(output_dir, "functions.json"),
        "analysis_file": os.path.join(output_dir, "analysis.json"),
        "prompts_file": os.path.join(output_dir, "prompts.jsonl")
    }

def generate_security_report(analysis_json_path):
    with open(analysis_json_path, 'r') as f:
        analysis_json = json.load(f)
    analysis_data = [entry["analysis"] for entry in analysis_json]
    num_vulnerabilities = len(analysis_data)
    severity_keywords = {
        "high": ["critical", "reentrancy", "race condition", "fund loss"],
        "medium": ["centralization", "censorship", "manipulation"],
        "low": ["unspecified", "unknown"]
    }
    severity_count = {"high": 0, "medium": 0, "low": 0}
    for entry in analysis_data:
        for severity, keywords in severity_keywords.items():
            if any(keyword in entry.lower() for keyword in keywords):
                severity_count[severity] += 1
    overall_assessment = "High" if severity_count["high"] > 0 else "Medium" if severity_count["medium"] > 0 else "Low"
    top_vulnerabilities = analysis_data[:3]
    safe_address = "Not Safe" if overall_assessment == "High" else "Safe"
    return {
        "num_vulnerabilities": num_vulnerabilities,
        "overall_assessment": overall_assessment,
        "top_vulnerabilities": top_vulnerabilities,
        "safe_address": safe_address
    }

def format_report_for_display(report):
    output = f"""
SMART CONTRACT SECURITY ASSESSMENT

Vulnerabilities Found: {report['num_vulnerabilities']}
Risk Level: {report['overall_assessment']}
Address Status: {report['safe_address']}

TOP ISSUES:
"""
    for i, vuln in enumerate(report['top_vulnerabilities'], 1):
        output += f"{i}. {vuln}\n\n"
    output += "\nRECOMMENDATION:\n"
    output += "Do not interact with this contract without addressing the security issues." if report['safe_address'] == "Not Safe" else "Exercise caution when interacting with this contract."
    return output.strip()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze smart contracts for security vulnerabilities")
    parser.add_argument("address", help="Contract address to analyze")
    parser.add_argument("--etherscan-key", default=os.getenv("ETHERSCAN_API_KEY"), help="Etherscan API key")
    parser.add_argument("--gemini-key", default=os.getenv("GEMINI_API_KEY"), help="Google Gemini API key")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    results = analyze_smart_contract(args.address, args.etherscan_key, args.gemini_key, args.output)
    print("\n✅ Analysis complete!")
    print(f"Contract: {results['contract_name']}")
    print(f"Results saved to {args.output}/")

    analysis_path = results["analysis_file"]
    report = generate_security_report(analysis_path)
    formatted_report = format_report_for_display(report)
    print(formatted_report)

    # Save Markdown report
    with open(os.path.join(args.output, "report.md"), "w") as f:
        f.write(formatted_report)

    print(f"📝 Markdown report saved to {args.output}/report.md")
    