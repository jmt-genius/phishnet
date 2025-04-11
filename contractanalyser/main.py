import os
import json
import google.generativeai as genai
from typing import List, Dict
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import contract_analyser as ca

load_dotenv()

app = FastAPI()

# Allow extension origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

class AddressInput(BaseModel):
    address: str

@app.post("/analyze")
async def analyze_contract(input: AddressInput):
    try:
        results = ca.analyze_smart_contract(
            input.address,
            ETHERSCAN_API_KEY,
            GEMINI_API_KEY,
            output_dir="output"
        )

        report = ca.generate_security_report(results["analysis_file"])
        markdown_report = ca.format_report_for_display(report)

        return {
            "safe_address": report["safe_address"],
            "risk_level": report["overall_assessment"],
            "top_vulnerabilities": report["top_vulnerabilities"],
            "markdown_report": markdown_report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


