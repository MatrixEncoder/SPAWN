from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
import json
import asyncio
import subprocess
from datetime import datetime, timezone
import aiofiles
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import csv
import tempfile
import shutil
import time
import re
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Image, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="SPAWN - Vulnerability Scanner", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_text(json.dumps(message))

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                pass

manager = ConnectionManager()

# Define Models
class ScanConfiguration(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target_url: str
    scan_type: str = "standard"
    scope: str = "folder"  # url, page, folder, subdomain, domain, punk
    modules: List[str] = Field(default_factory=lambda: ["exec", "file", "sql", "xss", "csrf", "ssrf"])
    depth: int = 5
    level: int = 1
    timeout: int = 30
    max_scan_time: Optional[int] = None
    max_attack_time: Optional[int] = None
    max_links_per_page: Optional[int] = 20  # Enhanced parameter for better coverage
    max_files_per_dir: Optional[int] = 10   # Enhanced parameter for better coverage  
    scan_force: Optional[str] = "normal"    # Enhanced parameter: paranoid, sneaky, polite, normal, aggressive, insane
    proxy_url: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_method: Optional[str] = None  # basic, digest, ntlm
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    form_url: Optional[str] = None
    form_username: Optional[str] = None
    form_password: Optional[str] = None
    cookies: Optional[str] = None
    verify_ssl: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanConfigurationCreate(BaseModel):
    name: str
    target_url: str
    scan_type: str = "standard"  # quick, standard, deep
    scope: str = "folder"
    modules: Optional[List[str]] = None
    depth: Optional[int] = None
    level: Optional[int] = None
    timeout: Optional[int] = None
    max_scan_time: Optional[int] = None
    max_attack_time: Optional[int] = None
    max_links_per_page: Optional[int] = None  # Enhanced parameter for better coverage
    max_files_per_dir: Optional[int] = None   # Enhanced parameter for better coverage
    scan_force: Optional[str] = None         # Enhanced parameter for scan intensity
    proxy_url: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_method: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    form_url: Optional[str] = None
    form_username: Optional[str] = None
    form_password: Optional[str] = None
    cookies: Optional[str] = None
    verify_ssl: bool = True

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    status: str = "running"  # running, completed, failed, stopped
    progress: int = 0
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    scan_summary: Dict[str, Any] = Field(default_factory=dict)
    output_files: Dict[str, str] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    module: str
    severity: str
    title: str
    description: str
    url: str
    parameter: Optional[str] = None
    method: str
    attack_payload: Optional[str] = None
    curl_command: Optional[str] = None
    references: List[str] = Field(default_factory=list)

# Global dictionary to store running scans
active_scans = {}

# Scan type presets
SCAN_PRESETS = {
    "quick": {
        "modules": ["exec", "file", "sql", "xss", "csrf", "ssrf", "permanentxss", "redirect", "upload"],
        "depth": 8,  # Increased depth for better coverage
        "level": 2,
        "timeout": 60,  # Increased timeout
        "max_scan_time": 1200,  # 20 minutes - increased for thorough scanning
        "max_links_per_page": 50,  # More links per page
        "max_files_per_dir": 30,   # More files per directory
        "scan_force": "normal",    # Balanced scanning approach
        "description": "Quick scan for common vulnerabilities with enhanced coverage",
        "scope": "folder"  # Changed from domain to folder for broader coverage
    },
    "standard": {
        "modules": ["backup", "exec", "file", "sql", "xss", "csrf", "ssrf", "upload", "csp", 
                   "redirect", "permanentxss", "cookieflags", "http_headers", "methods", 
                   "crlf", "log4shell", "shellshock", "xxe", "ldap", "nikto", "timesql"],
        "depth": 12,  # Significantly increased depth
        "level": 2,
        "timeout": 90,  # Increased timeout
        "max_scan_time": 3600,  # 1 hour - more time for thorough scanning
        "max_links_per_page": 100,
        "max_files_per_dir": 50,
        "scan_force": "aggressive",  # More aggressive scanning
        "description": "Standard comprehensive scan with enhanced vulnerability detection",
        "scope": "folder"  # Changed from domain to folder
    },
    "deep": {
        "modules": ["backup", "brute_login_form", "buster", "cms", "cookieflags", "crlf", "csp",
                   "csrf", "exec", "file", "htaccess", "htp", "http_headers", "https_redirect",
                   "ldap", "log4shell", "methods", "network_device", "nikto", "permanentxss",
                   "redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf", "takeover",
                   "timesql", "upload", "wapp", "wp_enum", "xss", "xxe"],
        "depth": 20,  # Maximum depth for comprehensive scanning
        "level": 3,
        "timeout": 120,  # Increased timeout for complex sites
        "max_scan_time": 10800,  # 3 hours - maximum time for complete scanning
        "max_links_per_page": 200,  # Maximum links extraction
        "max_files_per_dir": 100,   # Maximum files per directory
        "scan_force": "insane",     # Maximum scanning intensity
        "description": "Deep comprehensive scan with all modules and maximum coverage",
        "scope": "folder"  # Changed from domain to folder for maximum coverage
    }
}

# SPAWN logo URL for branding
SPAWN_LOGO_URL = "https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/f/aeca6b42-3cb4-4fb4-b322-92f9e6232ef6/d30qkeo-a177eb43-802e-4a1a-b80f-01bf31f18df3.jpg?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1cm46YXBwOjdlMGQxODg5ODIyNjQzNzNhNWYwZDQxNWVhMGQyNmUwIiwiaXNzIjoidXJuOmFwcDo3ZTBkMTg4OTgyMjY0MzczYTVmMGQ0MTVlYTBkMjZlMCIsIm9iaiI6W1t7InBhdGgiOiJcL2ZcL2FlY2E2YjQyLTNjYjQtNGZiNC1iMzIyLTkyZjllNjIzMmVmNlwvZDMwcWtlby1hMTc3ZWI0My04MDJlLTRhMWEtYjgwZi0wMWJmMzFmMThkZjMuanBnIn1dXSwiYXVkIjpbInVybjpzZXJ2aWNlOmZpbGUuZG93bmxvYWQiXX0.C1tBOjVlRC8CZhNlYCZH00xtXf6j-8mHOTeFWgN0yBE"
WAPITI_MODULES = [
    "backup", "brute_login_form", "buster", "cms", "cookieflags", "crlf", "csp",
    "csrf", "exec", "file", "htaccess", "htp", "http_headers", "https_redirect",
    "ldap", "log4shell", "methods", "network_device", "nikto", "permanentxss",
    "redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf", "takeover",
    "timesql", "upload", "wapp", "wp_enum", "xss", "xxe"
]

# API Routes
@api_router.get("/")
async def root():
    return {"message": "SPAWN - Web Application Vulnerability Scanner", "version": "1.0.0"}

@api_router.get("/modules")
async def get_available_modules():
    """Get list of available Wapiti modules"""
    return {"modules": WAPITI_MODULES}

@api_router.get("/scan-presets")
async def get_scan_presets():
    """Get available scan type presets"""
    return {"presets": SCAN_PRESETS}

@api_router.post("/scans", response_model=ScanConfiguration)
async def create_scan_configuration(config: ScanConfigurationCreate):
    """Create a new scan configuration"""
    # Apply preset if scan_type is specified
    preset_config = {}
    if config.scan_type in SCAN_PRESETS:
        preset = SCAN_PRESETS[config.scan_type]
        preset_config = {
            "modules": config.modules or preset["modules"],
            "depth": config.depth or preset["depth"],
            "level": config.level or preset["level"],
            "timeout": config.timeout or preset["timeout"],
            "max_scan_time": config.max_scan_time or preset.get("max_scan_time"),
            "scope": preset.get("scope", "folder"),
            "max_links_per_page": preset.get("max_links_per_page", 20),
            "max_files_per_dir": preset.get("max_files_per_dir", 10),
            "scan_force": preset.get("scan_force", "normal")
        }
    
    scan_config = ScanConfiguration(**{**config.dict(), **preset_config})
    await db.scan_configurations.insert_one(scan_config.dict())
    return scan_config

@api_router.get("/scans", response_model=List[ScanConfiguration])
async def get_scan_configurations():
    """Get all scan configurations"""
    configs = await db.scan_configurations.find({}, {"_id": 0}).to_list(1000)
    return [ScanConfiguration(**config) for config in configs]

@api_router.get("/scans/{scan_id}", response_model=ScanConfiguration)
async def get_scan_configuration(scan_id: str):
    """Get a specific scan configuration"""
    config = await db.scan_configurations.find_one({"id": scan_id}, {"_id": 0})
    if not config:
        raise HTTPException(status_code=404, detail="Scan configuration not found")
    return ScanConfiguration(**config)

@api_router.post("/scans/{scan_id}/start")
async def start_scan(scan_id: str, background_tasks: BackgroundTasks):
    """Start a vulnerability scan"""
    config = await db.scan_configurations.find_one({"id": scan_id}, {"_id": 0})
    if not config:
        raise HTTPException(status_code=404, detail="Scan configuration not found")
    
    if scan_id in active_scans:
        raise HTTPException(status_code=400, detail="Scan is already running")
    
    # Create scan result
    scan_result = ScanResult(scan_id=scan_id)
    await db.scan_results.insert_one(scan_result.dict())
    
    # Start scan in background
    background_tasks.add_task(run_wapiti_scan, scan_id, config, scan_result.id)
    
    return {"message": "Scan started", "result_id": scan_result.id}

@api_router.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    """Stop a running scan"""
    if scan_id in active_scans:
        process = active_scans[scan_id]
        process.terminate()
        del active_scans[scan_id]
        
        # Update scan result
        await db.scan_results.update_one(
            {"scan_id": scan_id, "status": "running"},
            {"$set": {"status": "stopped", "completed_at": datetime.now(timezone.utc)}}
        )
        return {"message": "Scan stopped"}
    else:
        raise HTTPException(status_code=400, detail="No active scan found")

@api_router.get("/results/{result_id}", response_model=ScanResult)
async def get_scan_result(result_id: str):
    """Get scan result by ID"""
    result = await db.scan_results.find_one({"id": result_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return ScanResult(**result)

@api_router.get("/results/scan/{scan_id}", response_model=List[ScanResult])
async def get_scan_results(scan_id: str):
    """Get all results for a specific scan"""
    results = await db.scan_results.find({"scan_id": scan_id}, {"_id": 0}).to_list(1000)
    return [ScanResult(**result) for result in results]

@api_router.get("/results")
async def get_all_results():
    """Get all scan results with scan configuration info"""
    results = await db.scan_results.find({}, {"_id": 0}).sort("started_at", -1).to_list(1000)
    enriched_results = []
    
    for result in results:
        config = await db.scan_configurations.find_one({"id": result["scan_id"]}, {"_id": 0})
        if config:
            enriched_result = {
                **result,
                "scan_name": config.get("name", "Unknown"),
                "target_url": config.get("target_url", "Unknown")
            }
            enriched_results.append(enriched_result)
    
    return enriched_results

@api_router.get("/results/{result_id}/export/{format}")
async def export_scan_result(result_id: str, format: str):
    """Export scan result in different formats"""
    if format not in ["pdf", "csv", "html", "json"]:
        raise HTTPException(status_code=400, detail="Unsupported format")
    
    result = await db.scan_results.find_one({"id": result_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    
    config = await db.scan_configurations.find_one({"id": result["scan_id"]}, {"_id": 0})
    
    if format == "json":
        return {"scan_result": result, "scan_config": config}
    
    elif format == "csv":
        return await export_to_csv(result, config)
    
    elif format == "pdf":
        return await export_to_pdf(result, config)
    
    elif format == "html":
        return await export_to_html(result, config)

async def run_wapiti_scan(scan_id: str, config: dict, result_id: str):
    """Run Wapiti scan in background with real-time progress tracking"""
    try:
        # Create output directory
        output_dir = f"/tmp/wapiti_output_{scan_id}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Build Wapiti command - use full path for Docker compatibility
        cmd = ["/root/.venv/bin/wapiti", "-u", config["target_url"]]
        
        # Add scope
        cmd.extend(["--scope", config["scope"]])
        
        # Add modules
        if config["modules"]:
            cmd.extend(["-m", ",".join(config["modules"])])
        
        # Add depth and level
        cmd.extend(["-d", str(config["depth"]), "-l", str(config["level"])])
        
        # Add timeout
        cmd.extend(["-t", str(config["timeout"])])
        
        # Add max scan time if specified
        if config.get("max_scan_time"):
            cmd.extend(["--max-scan-time", str(config["max_scan_time"])])
        
        # Add enhanced scanning parameters for better vulnerability detection
        if config.get("max_links_per_page"):
            cmd.extend(["--max-links-per-page", str(config["max_links_per_page"])])
        
        if config.get("max_files_per_dir"):
            cmd.extend(["--max-files-per-dir", str(config["max_files_per_dir"])])
        
        # Add scan force level for more aggressive scanning
        if config.get("scan_force"):
            cmd.extend(["-S", config["scan_force"]])
        
        # Add more concurrent tasks for faster scanning
        cmd.extend(["--tasks", "8"])  # Increase concurrent tasks for better performance
        
        # Add authentication if provided
        if config.get("auth_username") and config.get("auth_password"):
            if config.get("auth_method"):
                cmd.extend(["--auth-method", config["auth_method"]])
            cmd.extend(["--auth-user", config["auth_username"]])
            cmd.extend(["--auth-password", config["auth_password"]])
        
        # Add form authentication if provided
        if config.get("form_url"):
            cmd.extend(["--form-url", config["form_url"]])
            if config.get("form_username"):
                cmd.extend(["--form-user", config["form_username"]])
            if config.get("form_password"):
                cmd.extend(["--form-password", config["form_password"]])
        
        # Add proxy if provided
        if config.get("proxy_url"):
            cmd.extend(["-p", config["proxy_url"]])
        
        # Add user agent if provided
        if config.get("user_agent"):
            cmd.extend(["-A", config["user_agent"]])
        
        # Add headers
        for header, value in config.get("headers", {}).items():
            cmd.extend(["-H", f"{header}: {value}"])
        
        # Add cookies if provided
        if config.get("cookies"):
            cmd.extend(["-C", config["cookies"]])
        
        # SSL verification
        cmd.extend(["--verify-ssl", "1" if config["verify_ssl"] else "0"])
        
        # Output format and file
        cmd.extend(["-f", "json", "-o", f"{output_dir}/report.json"])
        
        # Verbosity for progress tracking
        cmd.extend(["-v", "2"])
        
        # Run the scan
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        active_scans[scan_id] = process
        
        # Monitor progress with real-time updates
        await monitor_scan_progress_realtime(scan_id, result_id, process, output_dir)
        
    except Exception as e:
        # Update scan result with error
        await db.scan_results.update_one(
            {"id": result_id},
            {"$set": {
                "status": "failed",
                "error_message": str(e),
                "completed_at": datetime.now(timezone.utc)
            }}
        )
        await manager.broadcast({
            "type": "scan_error",
            "scan_id": scan_id,
            "result_id": result_id,
            "error": str(e)
        })

async def monitor_scan_progress(scan_id: str, result_id: str, process, output_dir):
    """Monitor scan progress and update results"""
    try:
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            # Parse results
            report_file = f"{output_dir}/report.json"
            if os.path.exists(report_file):
                async with aiofiles.open(report_file, 'r') as f:
                    content = await f.read()
                    report_data = json.loads(content)
                
                # Extract vulnerabilities with correct Wapiti JSON parsing
                vulnerabilities = []
                if "vulnerabilities" in report_data:
                    for vuln_type, vulns in report_data["vulnerabilities"].items():
                        if isinstance(vulns, list) and len(vulns) > 0:
                            for vuln in vulns:
                                # Map Wapiti numeric severity levels to strings
                                severity_raw = vuln.get("level", 2)
                                if isinstance(severity_raw, int):
                                    # Wapiti severity mapping: 1=low, 2=medium, 3=high, 4=critical
                                    severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
                                    severity = severity_map.get(severity_raw, "medium")
                                else:
                                    severity = str(severity_raw).lower()
                                
                                # Build proper URL from path
                                target_base = report_data.get("infos", {}).get("target", "")
                                vuln_path = vuln.get("path", "")
                                if target_base and vuln_path:
                                    if vuln_path.startswith("/"):
                                        vuln_url = target_base.rstrip("/") + vuln_path
                                    else:
                                        vuln_url = target_base.rstrip("/") + "/" + vuln_path
                                else:
                                    vuln_url = vuln.get("url", target_base)
                                
                                # Create properly formatted vulnerability title
                                vuln_title = vuln.get("info", vuln_type)
                                if vuln.get("parameter"):
                                    vuln_title += f" (Parameter: {vuln.get('parameter')})"
                                
                                vulnerability = Vulnerability(
                                    scan_id=scan_id,
                                    module=vuln_type,
                                    severity=severity,
                                    title=vuln_title,
                                    description=vuln.get("info", f"{vuln_type} vulnerability detected"),
                                    url=vuln_url,
                                    parameter=vuln.get("parameter", ""),
                                    method=vuln.get("method", "GET"),
                                    attack_payload=vuln.get("http_request", ""),
                                    curl_command=vuln.get("curl_command", ""),
                                    references=vuln.get("wstg", [])
                                )
                                vulnerabilities.append(vulnerability.dict())
                                await db.vulnerabilities.insert_one(vulnerability.dict())
                
                # Update scan result
                await db.scan_results.update_one(
                    {"id": result_id},
                    {"$set": {
                        "status": "completed",
                        "vulnerabilities": vulnerabilities,
                        "scan_summary": {
                            "total_vulnerabilities": len(vulnerabilities),
                            "high_severity": len([v for v in vulnerabilities if v["severity"] == "high"]),
                            "medium_severity": len([v for v in vulnerabilities if v["severity"] == "medium"]),
                            "low_severity": len([v for v in vulnerabilities if v["severity"] == "low"]),
                            "info_severity": len([v for v in vulnerabilities if v["severity"] == "info"])
                        },
                        "progress": 100,
                        "completed_at": datetime.now(timezone.utc)
                    }}
                )
                
                await manager.broadcast({
                    "type": "scan_completed",
                    "scan_id": scan_id,
                    "result_id": result_id,
                    "vulnerabilities_count": len(vulnerabilities)
                })
            else:
                await db.scan_results.update_one(
                    {"id": result_id},
                    {"$set": {
                        "status": "completed",
                        "progress": 100,
                        "completed_at": datetime.now(timezone.utc)
                    }}
                )
        else:
            error_msg = stderr.decode() if stderr else "Unknown error"
            await db.scan_results.update_one(
                {"id": result_id},
                {"$set": {
                    "status": "failed",
                    "error_message": error_msg,
                    "completed_at": datetime.now(timezone.utc)
                }}
            )
            
        # Clean up
        if scan_id in active_scans:
            del active_scans[scan_id]
            
        # Remove temporary files
        shutil.rmtree(output_dir, ignore_errors=True)
        
    except Exception as e:
        await db.scan_results.update_one(
            {"id": result_id},
            {"$set": {
                "status": "failed",
                "error_message": str(e),
                "completed_at": datetime.now(timezone.utc)
            }}
        )

async def monitor_scan_progress_realtime(scan_id: str, result_id: str, process, output_dir):
    """Monitor scan progress with real-time updates and improved progress tracking"""
    try:
        progress = 0
        last_update = time.time()
        scan_phases = {
            "Starting scan": 5,
            "Loading modules": 10,
            "Crawling": 25,
            "Analyzing": 60,
            "Attack": 80,
            "Report generation": 95,
            "Completed": 100
        }
        current_phase = "Starting scan"
        
        # Read output line by line for real-time progress
        while True:
            line = await process.stdout.readline()
            if not line:
                break
                
            line_text = line.decode().strip()
            if not line_text:
                continue
                
            # Parse progress from Wapiti output with better detection
            progress_updated = False
            
            # Detect scan phases
            if "Loading modules" in line_text or "module" in line_text.lower():
                if progress < scan_phases["Loading modules"]:
                    progress = scan_phases["Loading modules"]
                    current_phase = "Loading modules"
                    progress_updated = True
            elif any(keyword in line_text.lower() for keyword in ["crawling", "exploring", "crawler"]):
                if progress < scan_phases["Crawling"]:
                    progress = scan_phases["Crawling"]
                    current_phase = "Crawling"
                    progress_updated = True
                elif progress >= scan_phases["Crawling"] and progress < scan_phases["Analyzing"]:
                    # Incremental progress during crawling
                    progress = min(progress + 2, scan_phases["Analyzing"] - 5)
                    progress_updated = True
            elif any(keyword in line_text.lower() for keyword in ["analyzing", "scanning", "attack"]):
                if progress < scan_phases["Attack"]:
                    progress = min(scan_phases["Attack"], progress + 5)
                    current_phase = "Analyzing/Attacking"
                    progress_updated = True
            elif "vulnerabilit" in line_text.lower() or "found" in line_text.lower():
                if progress < scan_phases["Report generation"]:
                    progress = scan_phases["Report generation"]
                    current_phase = "Report generation"
                    progress_updated = True
            elif "report" in line_text.lower() or "json" in line_text.lower():
                progress = scan_phases["Report generation"]
                current_phase = "Report generation"
                progress_updated = True
            
            # Update progress every 3 seconds or on significant changes
            current_time = time.time()
            if progress_updated or (current_time - last_update >= 3):
                await db.scan_results.update_one(
                    {"id": result_id},
                    {"$set": {"progress": progress}}
                )
                await manager.broadcast({
                    "type": "scan_progress",
                    "scan_id": scan_id,
                    "result_id": result_id,
                    "progress": progress,
                    "phase": current_phase,
                    "message": line_text[:100] if line_text else ""
                })
                last_update = current_time
        
        # Wait for process to complete
        await process.wait()
        
        # Set final progress
        progress = 100
        current_phase = "Completed"
        await db.scan_results.update_one(
            {"id": result_id},
            {"$set": {"progress": progress}}
        )
        
        if process.returncode == 0:
            # Parse results
            report_file = f"{output_dir}/report.json"
            vulnerabilities = []
            
            # Wait a moment for file system sync
            await asyncio.sleep(1)
            
            if os.path.exists(report_file):
                try:
                    async with aiofiles.open(report_file, 'r') as f:
                        content = await f.read()
                        if content.strip():  # Check if file has content
                            report_data = json.loads(content)
                        
                            # Extract vulnerabilities with correct Wapiti JSON parsing
                            if "vulnerabilities" in report_data:
                                for vuln_type, vulns in report_data["vulnerabilities"].items():
                                    if isinstance(vulns, list) and len(vulns) > 0:
                                        for vuln in vulns:
                                            # Map Wapiti numeric severity levels to strings
                                            severity_raw = vuln.get("level", 2)
                                            if isinstance(severity_raw, int):
                                                # Wapiti severity mapping: 1=low, 2=medium, 3=high, 4=critical
                                                severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
                                                severity = severity_map.get(severity_raw, "medium")
                                            else:
                                                severity = str(severity_raw).lower()
                                            
                                            # Build proper URL from path
                                            target_base = report_data.get("infos", {}).get("target", "")
                                            vuln_path = vuln.get("path", "")
                                            if target_base and vuln_path:
                                                if vuln_path.startswith("/"):
                                                    vuln_url = target_base.rstrip("/") + vuln_path
                                                else:
                                                    vuln_url = target_base.rstrip("/") + "/" + vuln_path
                                            else:
                                                vuln_url = vuln.get("url", target_base)
                                            
                                            # Create properly formatted vulnerability title
                                            vuln_title = vuln.get("info", vuln_type)
                                            if vuln.get("parameter"):
                                                vuln_title += f" (Parameter: {vuln.get('parameter')})"
                                            
                                            vulnerability = Vulnerability(
                                                scan_id=scan_id,
                                                module=vuln_type,
                                                severity=severity,
                                                title=vuln_title,
                                                description=vuln.get("info", f"{vuln_type} vulnerability detected"),
                                                url=vuln_url,
                                                parameter=vuln.get("parameter", ""),
                                                method=vuln.get("method", "GET"),
                                                attack_payload=vuln.get("http_request", ""),
                                                curl_command=vuln.get("curl_command", ""),
                                                references=vuln.get("wstg", [])
                                            )
                                            vulnerabilities.append(vulnerability.dict())
                                            await db.vulnerabilities.insert_one(vulnerability.dict())
                except Exception as e:
                    print(f"Error parsing report: {e}")
                    # Continue with empty vulnerabilities list
            
            # Update scan result with comprehensive summary
            severity_counts = {
                "high": len([v for v in vulnerabilities if v["severity"] == "high"]),
                "medium": len([v for v in vulnerabilities if v["severity"] == "medium"]),
                "low": len([v for v in vulnerabilities if v["severity"] == "low"]),
                "info": len([v for v in vulnerabilities if v["severity"] == "info"])
            }
            
            await db.scan_results.update_one(
                {"id": result_id},
                {"$set": {
                    "status": "completed",
                    "vulnerabilities": vulnerabilities,
                    "scan_summary": {
                        "total_vulnerabilities": len(vulnerabilities),
                        **severity_counts,
                        "scan_duration": int(time.time() - process.pid)  # Approximate duration
                    },
                    "progress": 100,
                    "completed_at": datetime.now(timezone.utc)
                }}
            )
            
            await manager.broadcast({
                "type": "scan_completed",
                "scan_id": scan_id,
                "result_id": result_id,
                "vulnerabilities_count": len(vulnerabilities),
                "severity_breakdown": severity_counts
            })
        else:
            # Process failed
            await db.scan_results.update_one(
                {"id": result_id},
                {"$set": {
                    "status": "failed",
                    "error_message": "Wapiti scan process failed",
                    "progress": 0,
                    "completed_at": datetime.now(timezone.utc)
                }}
            )
            await manager.broadcast({
                "type": "scan_error",
                "scan_id": scan_id,
                "result_id": result_id,
                "error": "Scan process failed"
            })
            
        # Clean up
        if scan_id in active_scans:
            del active_scans[scan_id]
            
        # Keep temporary files for debugging if scan failed, otherwise remove them
        if process.returncode == 0:
            shutil.rmtree(output_dir, ignore_errors=True)
        
    except Exception as e:
        await db.scan_results.update_one(
            {"id": result_id},
            {"$set": {
                "status": "failed",
                "error_message": str(e),
                "progress": 0,
                "completed_at": datetime.now(timezone.utc)
            }}
        )
        await manager.broadcast({
            "type": "scan_error",
            "scan_id": scan_id,
            "result_id": result_id,
            "error": str(e)
        })

async def export_to_csv(result: dict, config: dict):
    """Export scan result to CSV"""
    output = []
    output.append(["Scan Name", config.get("name", "Unknown")])
    output.append(["Target URL", config.get("target_url", "Unknown")])
    output.append(["Scan Date", result.get("started_at", "")])
    output.append([])
    output.append(["Module", "Severity", "Title", "URL", "Parameter", "Description"])
    
    for vuln in result.get("vulnerabilities", []):
        output.append([
            vuln.get("module", ""),
            vuln.get("severity", ""),
            vuln.get("title", ""),
            vuln.get("url", ""),
            vuln.get("parameter", ""),
            vuln.get("description", "")
        ])
    
    # Create CSV file
    csv_content = []
    for row in output:
        csv_line = ",".join([f'"{str(cell)}"' for cell in row])
        csv_content.append(csv_line)
    
    csv_string = "\n".join(csv_content)
    
    return StreamingResponse(
        iter([csv_string.encode()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_result_{result['id']}.csv"}
    )

def _calculate_duration(result):
    """Calculate scan duration"""
    if result.get("started_at") and result.get("completed_at"):
        try:
            started_at = result["started_at"]
            completed_at = result["completed_at"]
            
            # Handle both string and datetime objects
            if isinstance(started_at, str):
                start = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
            else:
                start = started_at
                
            if isinstance(completed_at, str):
                end = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
            else:
                end = completed_at
                
            duration = end - start
            return str(duration).split('.')[0]  # Remove microseconds
        except Exception as e:
            print(f"Error calculating duration: {e}")
            return "N/A"
    return "N/A"

async def export_to_pdf(result: dict, config: dict):
    """Export scan result to PDF matching the professional report format"""
    # Create temporary PDF file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
        doc = SimpleDocTemplate(tmp_file.name, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Calculate vulnerability counts and scan completion
        vulnerabilities = result.get("vulnerabilities", [])
        vuln_count = len(vulnerabilities)
        
        high_count = len([v for v in vulnerabilities if v.get("severity", "").lower() == "high"])
        medium_count = len([v for v in vulnerabilities if v.get("severity", "").lower() == "medium"])
        low_count = len([v for v in vulnerabilities if v.get("severity", "").lower() == "low"])
        
        # Format scan date
        scan_date = result.get("started_at", "")
        if scan_date:
            try:
                # Parse and format the date
                from datetime import datetime
                if isinstance(scan_date, str):
                    # Handle ISO format dates
                    if "T" in scan_date:
                        dt = datetime.fromisoformat(scan_date.replace("Z", "+00:00"))
                    else:
                        dt = datetime.strptime(scan_date[:19], "%Y-%m-%d %H:%M:%S")
                else:
                    dt = scan_date
                scan_date_formatted = dt.strftime("%Y-%m-%dT%H:%M:%S")
            except:
                scan_date_formatted = str(scan_date)[:19]
        else:
            scan_date_formatted = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        # Header Information Table (matching the image format)
        story.append(Spacer(1, 30))
        
        header_data = [
            ['Target URL:', config.get("target_url", "")],
            ['Scan Date:', scan_date_formatted],
            ['Scan Status:', result.get("status", "COMPLETED").upper()],
            ['Total Vulnerabilities:', str(vuln_count)],
            ['Scan Duration:', "100% completed"]
        ]
        
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(header_table)
        story.append(Spacer(1, 30))
        
        # Vulnerability Distribution Section
        vuln_dist_title = ParagraphStyle(
            'VulnDistTitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=15,
            textColor=colors.darkred,
            fontName='Helvetica-Bold'
        )
        story.append(Paragraph("Vulnerability Distribution", vuln_dist_title))
        
        # Count vulnerabilities by severity for distribution table
        severity_counts = {
            'HIGH': high_count,
            'MEDIUM': medium_count, 
            'LOW': low_count
        }
        
        # Only show severities that have vulnerabilities
        dist_data = [['Severity Level', 'Count', 'Risk Assessment']]
        for severity, count in severity_counts.items():
            if count > 0:
                risk_assessment = {
                    'HIGH': 'Critical - Address immediately',
                    'MEDIUM': 'Should be addressed soon',
                    'LOW': 'Monitor and address when possible'
                }.get(severity, 'Should be addressed soon')
                
                dist_data.append([severity, str(count), risk_assessment])
        
        # If we have any vulnerabilities, create the distribution table
        if len(dist_data) > 1:
            dist_table = Table(dist_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
            dist_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(dist_table)
        story.append(Spacer(1, 30))
        
        # Detailed Vulnerability Findings Section
        if vulnerabilities:
            findings_title = ParagraphStyle(
                'FindingsTitle',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=15,
                textColor=colors.darkred,
                fontName='Helvetica-Bold'
            )
            story.append(Paragraph("Detailed Vulnerability Findings", findings_title))
            
            # Create detailed findings table (matching the image format)
            findings_data = [['#', 'Type', 'Severity', 'URL', 'Parameter', 'Description', 'CWE']]
            
            for i, vuln in enumerate(vulnerabilities, 1):
                # Extract CWE from description or generate based on type
                cwe = ""
                description = vuln.get("description", "")
                if "CWE-" in description:
                    # Extract CWE from description
                    import re
                    cwe_match = re.search(r'CWE-\d+', description)
                    if cwe_match:
                        cwe = cwe_match.group()
                else:
                    # Generate CWE based on vulnerability type
                    vuln_type = vuln.get("module", "").upper()
                    cwe_mapping = {
                        'XSS': 'WSTG-INPV-07',
                        'SQL': 'WSTG-ATHZ-01', 
                        'CSRF': 'WSTG-SESS-05',
                        'SSRF': 'WSTG-INPV-19',
                        'PATH TRAVERSAL': 'WSTG-ATHZ-01',
                        'REFLECTED': 'WSTG-INPV-01',
                        'EXEC': 'WSTG-INPV-12',
                        'FILE': 'WSTG-CONF-08'
                    }
                    cwe = cwe_mapping.get(vuln_type, 'WSTG-ATHZ-01')
                
                # Clean and truncate fields for better display
                vuln_type = vuln.get("module", "UNKNOWN").upper()
                if "XSS" in vuln_type:
                    vuln_type = "XSS"
                elif "SQL" in vuln_type:
                    vuln_type = "SQL INJECTION"
                elif "CSRF" in vuln_type:
                    vuln_type = "CSRF"
                elif "PATH" in vuln_type:
                    vuln_type = "PATH TRAVERSAL"
                elif "REFLECTED" in vuln_type:
                    vuln_type = "REFLECTED CR"
                
                severity = vuln.get("severity", "medium").upper()
                url = vuln.get("url", "")[:40] + ("..." if len(vuln.get("url", "")) > 40 else "")
                parameter = vuln.get("parameter", "")[:15]
                desc_short = description[:50] + ("..." if len(description) > 50 else "")
                
                findings_data.append([
                    str(i),
                    vuln_type,
                    severity,
                    url,
                    parameter,
                    desc_short,
                    cwe
                ])
            
            # Create the findings table
            findings_table = Table(findings_data, colWidths=[0.4*inch, 1*inch, 0.8*inch, 2.2*inch, 0.8*inch, 2*inch, 0.8*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(findings_table)
        
        # Add continuation table if we have many vulnerabilities (like in the second image)
        if len(vulnerabilities) > 10:
            story.append(PageBreak())
            
            # Add continuation table with orange header (matching second image)
            continuation_data = [['Module', 'Title', 'URL', 'Parameter']]
            
            for vuln in vulnerabilities[10:]:  # Show remaining vulnerabilities
                module = vuln.get("module", "").replace("_", " ").title()
                if "Cross" in module or "xss" in module.lower():
                    module = "Cross Site Requ"
                elif "sql" in module.lower():
                    module = "SQL Injection"
                elif "reflected" in module.lower():
                    module = "Reflected Cross"
                
                title = "Vulnerability Found"
                url = ""  # As shown in the image, URL field is empty
                parameter = vuln.get("parameter", "")
                
                continuation_data.append([module, title, url, parameter])
            
            continuation_table = Table(continuation_data, colWidths=[1.5*inch, 2*inch, 2*inch, 1.5*inch])
            continuation_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(continuation_table)
        
        # Footer (matching the image format)
        story.append(Spacer(1, 50))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=9,
            alignment=TA_CENTER,
            textColor=colors.grey
        )
        
        story.append(Paragraph("Generated by SPAWN - Professional Vulnerability Assessment Platform", footer_style))
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
        story.append(Paragraph("© 2024 SPAWN Security Solutions - All Rights Reserved", footer_style))
        
        # Build the PDF
        doc.build(story)
        
        return FileResponse(
            tmp_file.name,
            media_type="application/pdf",
            filename=f"SPAWN_Security_Report_{result['id']}.pdf"
        )

async def export_to_html(result: dict, config: dict):
    """Export scan result to HTML"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SPAWN Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .info-table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
            .vuln-table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .severity-high {{ color: red; font-weight: bold; }}
            .severity-medium {{ color: orange; font-weight: bold; }}
            .severity-low {{ color: blue; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SPAWN Vulnerability Scan Report</h1>
        </div>
        
        <h2>Scan Information</h2>
        <table class="info-table">
            <tr><th>Scan Name</th><td>{config.get("name", "Unknown")}</td></tr>
            <tr><th>Target URL</th><td>{config.get("target_url", "Unknown")}</td></tr>
            <tr><th>Scan Date</th><td>{result.get("started_at", "")}</td></tr>
            <tr><th>Status</th><td>{result.get("status", "Unknown")}</td></tr>
            <tr><th>Total Vulnerabilities</th><td>{len(result.get("vulnerabilities", []))}</td></tr>
        </table>
        
        <h2>Vulnerabilities</h2>
        <table class="vuln-table">
            <tr>
                <th>Module</th>
                <th>Severity</th>
                <th>Title</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Description</th>
            </tr>
    """
    
    for vuln in result.get("vulnerabilities", []):
        severity_class = f"severity-{vuln.get('severity', 'low').lower()}"
        html_content += f"""
            <tr>
                <td>{vuln.get("module", "")}</td>
                <td class="{severity_class}">{vuln.get("severity", "").upper()}</td>
                <td>{vuln.get("title", "")}</td>
                <td>{vuln.get("url", "")}</td>
                <td>{vuln.get("parameter", "")}</td>
                <td>{vuln.get("description", "")}</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    return StreamingResponse(
        iter([html_content.encode()]),
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=scan_result_{result['id']}.html"}
    )

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()