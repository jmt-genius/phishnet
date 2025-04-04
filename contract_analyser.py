import os
import json
import google.generativeai as genai
from typing import List, Dict

# Step 1: Fetch contract source from Etherscan
def fetch_contract_source(address: str, api_key: str) -> dict:
    """Fetch verified source code from Etherscan"""
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
    """Save contract source code to files"""
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        source_code_json = json.loads(source_code_raw.strip().lstrip('{').rstrip('}'))
        # Handle multi-file contracts
        if isinstance(source_code_json, dict):
            for file_path, file_content in source_code_json.items():
                if isinstance(file_content, dict) and "content" in file_content:
                    content = file_content["content"]
                else:
                    content = file_content
                
                full_path = os.path.join(output_dir, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                with open(full_path, "w") as f:
                    f.write(content)
            
            return os.path.join(output_dir, contract_name + ".sol")
        else:
            raise ValueError("Unrecognized multi-file contract format.")
    
    except json.JSONDecodeError:
        # Handle single file contracts
        filename = os.path.join(output_dir, f"{contract_name}.sol")
        with open(filename, "w") as f:
            f.write(source_code_raw)
        
        return filename

# Step 3: Extract functions using Slither
def extract_functions_with_slither(contract_path):
    """Extract functions from contract using Slither"""
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
                "state_mutability": getattr(function, "state_mutability", "unknown")
            })
    
    return functions

def chunk_functions(functions: List[Dict], max_tokens: int = 6000):
    """Split functions into manageable chunks for LLM analysis"""
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
    """Analyze function chunks with Gemini API"""
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

def generate_prompts(functions, contract_name):
    """Generate detailed prompts for specific functions"""
    prompts = []
    
    for fn in functions:
        name = fn["name"]
        params = ", ".join(fn["parameters"])
        visibility = fn.get("visibility", "public")
        modifiers = ", ".join(fn.get("modifiers", []))
        returns = ", ".join(fn.get("returns", [])) if fn.get("returns") else "none"
        state = fn.get("state_mutability", "nonpayable")
        
        header = f"[Function `{name}` from {contract_name}]\n"
        sig = f"function {name}({params}) {visibility} {modifiers}".strip()
        
        if state and state != "nonpayable":
            sig += f" {state}"
        
        if returns and returns != "none":
            sig += f" returns ({returns})"
        
        prompt = f"""{header}{sig}
        Q: Are there any security vulnerabilities or high-risk patterns in this function?
        Explain in detail with examples if possible."""
        
        prompts.append({
            "function_name": name,
            "prompt": prompt
        })
    
    return prompts

def analyze_smart_contract(contract_address, etherscan_api_key, gemini_api_key, output_dir="output"):
    """Complete workflow for smart contract analysis"""
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Fetching contract at {contract_address}...")
    contract_data = fetch_contract_source(contract_address, etherscan_api_key)
    
    contract_path = save_contract_files(
        contract_data["contract_name"], 
        contract_data["source_code"],
        os.path.join(output_dir, "contracts")
    )
    print(f"Contract saved to {contract_path}")
    
    # Step 3: Extract functions
    print("Extracting functions with Slither...")
    functions = extract_functions_with_slither(contract_path)
    functions_file = os.path.join(output_dir, "functions.json")
    with open(functions_file, "w") as f:
        json.dump(functions, f, indent=2)
    print(f"Extracted {len(functions)} functions to {functions_file}")
    
    # Step 4: Chunk functions
    print("Chunking functions for analysis...")
    chunks = chunk_functions(functions)
    for i, chunk in enumerate(chunks):
        chunk_file = os.path.join(output_dir, f"chunk_{i}.json")
        with open(chunk_file, "w") as f:
            json.dump(chunk, f, indent=2)
    print(f"Created {len(chunks)} chunks for analysis")
    
    # Step 5: Analyze with Gemini
    print("Analyzing functions with Gemini...")
    analysis = analyze_with_gemini(chunks, gemini_api_key)
    analysis_file = os.path.join(output_dir, "analysis.json")
    with open(analysis_file, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"Analysis saved to {analysis_file}")
    
    # Step 6: Generate detailed prompts
    print("Generating detailed prompts...")
    prompts = generate_prompts(functions, contract_data["contract_name"])
    prompts_file = os.path.join(output_dir, "prompts.jsonl")
    with open(prompts_file, "w") as f:
        for p in prompts:
            f.write(json.dumps(p) + "\n")
    print(f"Generated {len(prompts)} detailed prompts to {prompts_file}")
    
    return {
        "contract_name": contract_data["contract_name"],
        "contract_path": contract_path,
        "functions_file": functions_file,
        "analysis_file": analysis_file,
        "prompts_file": prompts_file
    }
def generate_security_report(analysis_json_path):
    """
    Generate a human-readable security report from analysis.json
    
    Args:
        analysis_json_path: Path to the analysis.json file
    
    Returns:
        A dictionary containing the formatted security report
    """

    
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
    
    if severity_count["high"] > 0:
        overall_assessment = "High"
    elif severity_count["medium"] > 0:
        overall_assessment = "Medium"
    else:
        overall_assessment = "Low"
    
    top_vulnerabilities = analysis_data[:3]
    
    safe_address = "Not Safe" if overall_assessment == "High" else "Safe"
    
    report = {
        "num_vulnerabilities": num_vulnerabilities,
        "overall_assessment": overall_assessment,
        "top_vulnerabilities": top_vulnerabilities,
        "safe_address": safe_address
    }
    
    return report

def format_report_for_display(report):
    """
    Format the security report for display in a popup
    
    Args:
        report: The security report dictionary
    
    Returns:
        A formatted string for display
    """
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
    
    if report['safe_address'] == "Not Safe":
        output += "Do not interact with this contract without addressing the security issues."
    else:
        output += "Exercise caution when interacting with this contract."
    
    return output.strip()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze smart contracts for security vulnerabilities")
    parser.add_argument("address", help="Contract address to analyze")
    parser.add_argument("--etherscan-key", required=True, help="Etherscan API key")
    parser.add_argument("--gemini-key", required=True, help="Google Gemini API key")
    parser.add_argument("--output", default="output", help="Output directory")
    
    args = parser.parse_args()
    
    results = analyze_smart_contract(
        args.address,
        args.etherscan_key,
        args.gemini_key,
        args.output
    )
    
    print("\nAnalysis complete!")
    print(f"Contract: {results['contract_name']}")
    print(f"Results saved to {args.output}/")
    analysis_path = "./Result/analysis.json"
    report = generate_security_report(analysis_path)
    formatted_report = format_report_for_display(report)
    print(formatted_report)