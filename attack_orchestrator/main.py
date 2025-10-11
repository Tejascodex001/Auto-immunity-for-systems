# This is the exact, correct code from the first example.
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import shlex

app = FastAPI(
    title="Attack Orchestrator API",
    description="An API to launch controlled attacks from a sandboxed environment."
)

class AttackRequest(BaseModel):
    target: str = Field(..., description="The target IP address or hostname. E.g., 'victim-website'")

# Add more specific request models for each tool
class NmapRequest(AttackRequest):
    args: str = Field("-sV -p 80,443", description="A string of sanitized arguments for Nmap.")

class GobusterRequest(AttackRequest):
    # The target should be a full URL, e.g., http://victim-website
   wordlist: str = Field("/usr/share/wordlists/common.txt", description="Path to the wordlist inside the container.")

class CurlRequest(AttackRequest):
    args: str = Field("", description="Additional sanitized arguments for curl. E.g., '-A \"MaliciousBot/1.0\"'")

def run_command(command: list[str]) -> str:
    """Securely executes a command and captures its output."""
    try:
        print(f"Executing command: {' '.join(shlex.quote(arg) for arg in command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=120
        )
        return result.stdout
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Command not found: {command[0]}")
    except subprocess.CalledProcessError as e:
        error_message = f"Command failed with exit code {e.returncode}.\nStderr: {e.stderr}"
        raise HTTPException(status_code=400, detail=error_message)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command timed out.")

@app.get("/")
def read_root():
    return {"status": "Attack Orchestrator is operational."}

@app.post("/attack/nmap", summary="Run an Nmap scan")
def execute_nmap(req: NmapRequest):
    # shlex.split handles arguments safely
    command = ["nmap"] + shlex.split(req.args) + [req.target]
    output = run_command(command)
    return {"tool": "nmap", "target": req.target, "output": output}

@app.post("/attack/gobuster", summary="Run a Gobuster directory scan")
def execute_gobuster(req: GobusterRequest):
    # For Gobuster, the command structure is more fixed
    command = ["gobuster", "dir", "-u", req.target, "-w", req.wordlist]
    output = run_command(command)
    return {"tool": "gobuster", "target": req.target, "output": output}

# Add this new function at the end of the file, with the other endpoints
@app.post("/attack/curl", summary="Execute a single curl request")
def execute_curl(req: CurlRequest):
    """
    Executes a single, precise curl request. Excellent for crafting specific log entries.
    Target should be a full URL like http://victim-website/path
    """
    # shlex.split is critical for security here
    command = ["curl", "-s", "-o", "/dev/null"] + shlex.split(req.args) + [req.target]
    # -s: silent mode
    # -o /dev/null: discard the output, we only care if the request was made
    
    # We run the command but don't need its output, just confirmation it ran.
    run_command(command)
    return {"tool": "curl", "target": req.target, "args": req.args, "status": "request sent"}