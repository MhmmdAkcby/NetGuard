from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from scanner import scan_network
import uvicorn
import os

app = FastAPI(title="Network Scanner API")

# Ensure directories exist
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize templates
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """
    Renders the main dashboard.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/scan")
async def api_scan(subnet: str = Query("192.168.1.0/24", description="Subnet to scan")):
    """
    Endpoint to trigger a network scan.
    """
    try:
        results = await scan_network(subnet)
        return {"status": "success", "data": results}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanning failed: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
