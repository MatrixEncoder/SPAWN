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
    scope: str = "folder"  # url, page, folder, subdomain, domain, punk
    modules: List[str] = Field(default_factory=lambda: ["exec", "file", "sql", "xss", "csrf", "ssrf"])
    depth: int = 5
    level: int = 1
    timeout: int = 30
    max_scan_time: Optional[int] = None
    max_attack_time: Optional[int] = None
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
    scope: str = "folder"
    modules: List[str] = Field(default_factory=lambda: ["exec", "file", "sql", "xss", "csrf", "ssrf"])
    depth: int = 5
    level: int = 1
    timeout: int = 30
    max_scan_time: Optional[int] = None
    max_attack_time: Optional[int] = None
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

# Available Wapiti modules
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

@api_router.post("/scans", response_model=ScanConfiguration)
async def create_scan_configuration(config: ScanConfigurationCreate):
    """Create a new scan configuration"""
    scan_config = ScanConfiguration(**config.dict())
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
    config = await db.scan_configurations.find_one({"id": scan_id})
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
    result = await db.scan_results.find_one({"id": result_id})
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return ScanResult(**result)

@api_router.get("/results/scan/{scan_id}", response_model=List[ScanResult])
async def get_scan_results(scan_id: str):
    """Get all results for a specific scan"""
    results = await db.scan_results.find({"scan_id": scan_id}).to_list(1000)
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
    """Run Wapiti scan in background"""
    try:
        # Create output directory
        output_dir = f"/tmp/wapiti_output_{scan_id}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Build Wapiti command
        cmd = ["wapiti", "-u", config["target_url"]]
        
        # Add scope
        cmd.extend(["--scope", config["scope"]])
        
        # Add modules
        if config["modules"]:
            cmd.extend(["-m", ",".join(config["modules"])])
        
        # Add depth and level
        cmd.extend(["-d", str(config["depth"]), "-l", str(config["level"])])
        
        # Add timeout
        cmd.extend(["-t", str(config["timeout"])])
        
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
            stderr=asyncio.subprocess.PIPE
        )
        
        active_scans[scan_id] = process
        
        # Monitor progress
        await monitor_scan_progress(scan_id, result_id, process, output_dir)
        
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
                
                # Extract vulnerabilities
                vulnerabilities = []
                if "vulnerabilities" in report_data:
                    for vuln_type, vulns in report_data["vulnerabilities"].items():
                        for vuln in vulns:
                            vulnerability = Vulnerability(
                                scan_id=scan_id,
                                module=vuln_type,
                                severity=vuln.get("level", "medium"),
                                title=vuln.get("title", "Vulnerability Found"),
                                description=vuln.get("description", ""),
                                url=vuln.get("url", ""),
                                parameter=vuln.get("parameter", ""),
                                method=vuln.get("method", "GET"),
                                attack_payload=vuln.get("payload", ""),
                                curl_command=vuln.get("curl_command", ""),
                                references=vuln.get("references", [])
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

async def export_to_pdf(result: dict, config: dict):
    """Export scan result to PDF"""
    # Create temporary PDF file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
        doc = SimpleDocTemplate(tmp_file.name, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("SPAWN Vulnerability Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Scan Information
        info_data = [
            ['Scan Name:', config.get("name", "Unknown")],
            ['Target URL:', config.get("target_url", "Unknown")],
            ['Scan Date:', result.get("started_at", "")],
            ['Status:', result.get("status", "Unknown")],
        ]
        
        info_table = Table(info_data)
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        story.append(Spacer(1, 24))
        
        # Vulnerabilities
        if result.get("vulnerabilities"):
            story.append(Paragraph("Vulnerabilities Found", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            vuln_data = [['Module', 'Severity', 'Title', 'URL']]
            for vuln in result["vulnerabilities"][:20]:  # Limit to first 20
                vuln_data.append([
                    vuln.get("module", "")[:15],
                    vuln.get("severity", ""),
                    vuln.get("title", "")[:30],
                    vuln.get("url", "")[:40]
                ])
            
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
        
        doc.build(story)
        
        return FileResponse(
            tmp_file.name,
            media_type="application/pdf",
            filename=f"scan_result_{result['id']}.pdf"
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