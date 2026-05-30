from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import subprocess
import os

app = FastAPI(title="VibeSec SaaS")

# Ensure templates directory exists
os.makedirs("templates", exist_ok=True)
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"result": None, "error": None})

@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, path: str = Form(...)):
    if not path:
        return templates.TemplateResponse(request=request, name="index.html", context={"result": None, "error": "Path cannot be empty"})

    try:
        # Note: In a real SaaS, scanning arbitrary paths on the server is highly dangerous.
        # This is for demonstration purposes. A real implementation would upload files to a temporary sandbox.
        result = subprocess.run(
            ["python", "scanner/cli/vibesec.py", "scan", path],
            capture_output=True,
            text=True,
            check=False
        )
        output = result.stdout + result.stderr
        return templates.TemplateResponse(request=request, name="index.html", context={"result": output, "error": None, "path": path})
    except Exception as e:
         return templates.TemplateResponse(request=request, name="index.html", context={"result": None, "error": f"Scan failed: {e}", "path": path})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
