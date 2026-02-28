import time
import hashlib
import docker
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# --- CONFIGURATION ---
SECRET_SALT = "BNMIT_ECLIPSE_2026"
MORPH_INTERVAL = 60 

# Initialize Docker
try:
    client = docker.from_env()
except:
    client = None

# --- STEP 2: THREAT DETECTION BRAIN ---
class ThreatDetector:
    def __init__(self):
        self.ip_risks = {}

    def calculate_risk(self, ip, is_valid_path):
        if ip not in self.ip_risks:
            self.ip_risks[ip] = 0.0
        if not is_valid_path:
            self.ip_risks[ip] += 0.25 # 4 wrong hits = Redirection
        return min(self.ip_risks[ip], 1.0)

detector = ThreatDetector()

def get_current_hash():
    window = int(time.time() // MORPH_INTERVAL)
    return hashlib.sha256(f"{window}{SECRET_SALT}".encode()).hexdigest()[:8]

# --- ADSM MIDDLEWARE ---
@app.middleware("http")
async def adsm_logic(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path
    
    if path == "/" or path == "/status":
        return await call_next(request)

    current_hash = get_current_hash()
    is_valid = path.startswith(f"/gate-{current_hash}")
    risk_score = detector.calculate_risk(client_ip, is_valid)

    # Log the threat for our Dashboard
    with open("alerts.log", "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} | IP: {client_ip} | Risk: {risk_score} | Path: {path}\n")

    # Step 3: Deception Trigger
    if risk_score >= 0.75:
        if client:
            try:
                # Spawns the Docker trap
                client.containers.run("nginx:alpine", detach=True, ports={'80/tcp': 8081}, remove=True)
            except:
                pass 
        return JSONResponse(
            status_code=302,
            content={"alert": "DECEPTION ACTIVE", "redirect": "http://127.0.0.1:8081"}
        )

    if not is_valid:
        return JSONResponse(status_code=404, content={"error": "Surface Mismatch", "risk": risk_score})

    return await call_next(request)

# --- ENDPOINTS ---
@app.get("/gate-{morph_hash}/vault")
async def secure_vault(morph_hash: str):
    return {"status": "Success", "data": "ISRO_PAYLOAD_DATA_ALPHA"}

@app.get("/status")
async def status():
    return {"active_gate": f"/gate-{get_current_hash()}/vault"}
