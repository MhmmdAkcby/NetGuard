# FIXED BUGS:
# BUG 5 - websocket_scan(): Tracked background save task to prevent silent data loss.

import sys
import asyncio

# Windows-specific fix for 'NotImplementedError' when using subprocesses
# This MUST be set before any loops are created.
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, Request, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends, status, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
import uvicorn
import os

import logging
import json
from datetime import datetime, timedelta

from scanner import scan_network_stream, update_mac_database, get_interfaces, DiscoveryManager, discovery_manager, scan_surrounding_networks_stream
from database import init_db, save_scan_results, get_latest_scans, get_alerts, save_alert, get_latest_full_scan, save_network_health, save_config, get_config, get_history_timeline
from cve_updater import update_cve_database, get_cve_stats
from ids_engine import IDSEngine
from security_engine import security_engine
from wifi_pentest.engine import PentestEngine
from wifi_pentest.terminal import TerminalSession, TerminalSessionManager

# --- SSE Event Queue ---
event_queue = asyncio.Queue()

# --- Background Task & Scheduling ---
scheduler = AsyncIOScheduler()

async def scheduled_scan():
    subnet = await get_config("last_subnet")
    interface = await get_config("last_interface")
    if not subnet: return
    
    logger.info(f"Starting scheduled scan on {subnet}...")
    async for update in scan_network_stream(subnet, interface, speed="Normal"):
        if update["type"] == "final_data":
            alerts, score = await analyze_security_changes(update["data"])
            for alert in alerts: await event_queue.put(alert)
            await save_scan_results(update["data"])

# --- IDS Initialization ---
async def handle_ids_alert(alert):
    logger.warning(f"IDS ALERT: {alert['msg']}")
    # Save to database
    await save_alert(alert['sev'], alert['type'], alert['msg'], alert['ip'])
    # Push to SSE
    await event_queue.put(alert)

ids_engine = IDSEngine(handle_ids_alert, gateway_callback=security_engine.set_config)
pentest_engine = PentestEngine()
terminal_manager = TerminalSessionManager(max_sessions=10)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await update_mac_database()
    await pentest_engine.initialize()

    
    # Start IDS
    try:
        interface = await get_config("last_interface")
        ids_engine.start(interface)
    except Exception as e:
        logger.error(f"Failed to start Security Services: {e}")

    interval = int(await get_config("scan_interval", "5"))
    scheduler.add_job(scheduled_scan, 'interval', minutes=interval, id="scheduled_scan", replace_existing=True)
    scheduler.add_job(update_cve_database, 'interval', hours=24, id="cve_update", replace_existing=True)
    scheduler.start()
    yield
    await terminal_manager.destroy_all()
    scheduler.shutdown()

app = FastAPI(title="NetGuard Security Hub", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NetGuard")

async def analyze_security_changes(new_results):
    old_results = await get_latest_full_scan()
    old_map = {d['ip']: d for d in old_results}
    new_map = {d['ip']: d for d in new_results}
    alerts = []
    for ip, dev in new_map.items():
        if ip not in old_map:
            alerts.append({"sev": "Medium", "type": "New Device", "msg": f"New device {ip} joined the network", "ip": ip})
        for vuln in dev.get("vulnerabilities", []):
            alerts.append({"sev": vuln.get("severity", "Low"), "type": "Vulnerability", "msg": f"{vuln.get('cve', 'Unknown')} on {ip}", "ip": ip})
    for ip in old_map:
        if ip not in new_map:
            alerts.append({"sev": "Low", "type": "Device Left", "msg": f"Device {ip} disconnected", "ip": ip})
    for a in alerts: await save_alert(a['sev'], a['type'], a['msg'], a['ip'])
    total_risk = sum(d.get('risk_score', 0) for d in new_results)
    network_score = max(0, 100 - (total_risk + len(alerts) * 2))
    await save_network_health(len(new_results), network_score, 0)
    return alerts, network_score

@app.get("/api/events")
async def sse_events():
    async def event_generator():
        while True:
            alert = await event_queue.get()
            yield f"data: {json.dumps(alert)}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/interfaces")
async def api_interfaces():
    return {"status": "success", "data": get_interfaces()}

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    from scanner import PassiveEngine # Local import
    
    passive_engine = None
    
    try:
        params_data = await websocket.receive_text()
        params = json.loads(params_data)
        subnet = params.get("subnet")
        interface = params.get("interface")
        speed = params.get("speed", "Normal")
        passive = params.get("passive", False)
        surrounding = params.get("surrounding", False)
        
        await save_config("last_subnet", subnet)
        await save_config("last_interface", interface)

        if surrounding:
            # Surrounding WiFi Scan
            async for update in scan_surrounding_networks_stream():
                await websocket.send_json(update)
        elif passive:
            # Netdiscover Passive Mode Handler
            def on_passive_device(data):
                asyncio.run_coroutine_threadsafe(websocket.send_json({"type": "device", "data": data}), asyncio.get_event_loop())

            from scanner import PassiveEngine
            passive_engine = PassiveEngine(callback=on_passive_device)
            passive_engine.start(interface)
            
            # Keep socket alive and check for messages (to stop)
            # Keep socket alive and check for disconnects
            while True:
                try:
                    # Non-blocking check for messages or disconnects
                    await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                except asyncio.TimeoutError:
                    # Normal timeout, just continue loop
                    await asyncio.sleep(0.9)
                except WebSocketDisconnect:
                    break
                except Exception:
                    break
        else:
            # Active Mode
            async for update in scan_network_stream(subnet, interface, speed=speed, passive=False):
                if update["type"] == "final_data":
                    alerts, score = await analyze_security_changes(update["data"])
                    await websocket.send_json({"type": "security_report", "alerts": alerts, "score": score})
                    task = asyncio.create_task(save_scan_results(update["data"]))
                    background_tasks = getattr(websocket.app.state, "bg_tasks", set())
                    background_tasks.add(task)
                    task.add_done_callback(background_tasks.discard)
                    websocket.app.state.bg_tasks = background_tasks
                await websocket.send_json(update)
                
    except Exception as e: 
        logger.error(f"WS Error: {e}")
        try: await websocket.send_json({"type": "error", "message": str(e)})
        except: pass
    finally:
        if passive_engine: passive_engine.stop()
        try: await websocket.close()
        except: pass

@app.get("/api/cve/update")
async def trigger_cve_update():
    asyncio.create_task(update_cve_database())
    return {"status": "updating", "last_updated": datetime.now().isoformat()}

@app.get("/api/bandwidth")
async def api_bandwidth():
    return {"status": "success", "data": ids_engine.get_bandwidth_stats()}

@app.get("/api/history/timeline")
async def api_history_timeline(date: str = None):
    return {"status": "success", "data": await get_history_timeline(date)}

@app.post("/api/security/block")
async def api_block_device(request: Request):
    body = await request.json()
    ip = body.get("ip")
    mac = body.get("mac")
    if not ip or not mac: raise HTTPException(400, "IP and MAC required")
    
    # Sync gateway just in case it changed
    security_engine.set_config(ids_engine.interface, ids_engine.gateway_ip)
    
    success = security_engine.start_blocking(ip, mac)
    return {"status": "success" if success else "failed"}

@app.post("/api/security/unblock")
async def api_unblock_device(request: Request):
    body = await request.json()
    ip = body.get("ip")
    if not ip: raise HTTPException(400, "IP required")
    
    success = security_engine.stop_blocking(ip)
    return {"status": "success" if success else "failed"}

@app.get("/api/security/status")
async def api_security_status():
    return {"status": "success", "blocked_devices": list(security_engine.blocking_tasks.keys())}

@app.get("/api/cve/stats")
async def api_cve_stats():
    return {"status": "success", "data": await get_cve_stats()}

@app.get("/api/alerts")
async def api_alerts(
    limit: int = Query(50), 
    page: int = Query(1), 
    severity: str = Query(None),
    start_date: str = Query(None),
    end_date: str = Query(None)
):
    offset = (page - 1) * limit
    data = await get_alerts(limit, offset, severity, start_date, end_date)
    return {"status": "success", "data": data["items"], "total": data["total"], "page": page, "limit": limit}

@app.get("/api/history")
async def api_history(
    limit: int = Query(50), 
    page: int = Query(1), 
    ip: str = Query(None),
    start_date: str = Query(None),
    end_date: str = Query(None)
):
    offset = (page - 1) * limit
    data = await get_latest_scans(limit, offset, ip, start_date, end_date)
    return {"status": "success", "data": data["items"], "total": data["total"], "page": page, "limit": limit}

# --- Settings API ---
DEFAULT_SETTINGS = {
    "scan_speed": "Normal",
    "scan_interval": "5",
    "custom_ports": "",
    "last_subnet": "",
    "last_interface": "",
    "passive_mode": "false",
    "auto_scan": "false"
}

@app.get("/api/settings")
async def api_get_settings():
    settings = {}
    for key, default in DEFAULT_SETTINGS.items():
        settings[key] = await get_config(key, default)
    return {"status": "success", "data": settings}

@app.post("/api/settings")
async def api_save_settings(request: Request):
    body = await request.json()
    saved = {}
    for key, value in body.items():
        if key in DEFAULT_SETTINGS:
            await save_config(key, str(value))
            saved[key] = value
    # Dynamically reschedule if scan_interval changed
    if "scan_interval" in saved:
        try:
            new_interval = int(saved["scan_interval"])
            if new_interval >= 1:
                scheduler.reschedule_job("scheduled_scan", trigger="interval", minutes=new_interval)
                logger.info(f"Scan interval updated to {new_interval} minutes")
        except Exception as e:
            logger.error(f"Failed to reschedule scan: {e}")
    return {"status": "success", "data": saved}

# --- WiFi Pentest API Endpoints ---
@app.get("/api/pentest/status")
async def api_pentest_status():
    return {"status": "success", "data": await pentest_engine.get_monitor_status()}

@app.post("/api/pentest/monitor/start")
async def api_pentest_monitor_start(request: Request):
    body = await request.json()
    interface = body.get("interface")
    if not interface:
        return {"status": "error", "message": "Interface required"}
    res = await pentest_engine.enable_monitor_mode(interface)
    return {"status": "success" if res["success"] else "error", "data": res}

@app.post("/api/pentest/monitor/stop")
async def api_pentest_monitor_stop():
    res = await pentest_engine.disable_monitor_mode()
    return {"status": "success" if res["success"] else "error", "data": res}

@app.post("/api/pentest/scan/start")
async def api_pentest_scan_start(request: Request):
    body = await request.json()
    res = await pentest_engine.start_scan(
        interface=body.get("interface"),
        channel=body.get("channel"),
        bssid=body.get("bssid"),
        essid=body.get("essid")
    )
    return {"status": "success" if res["success"] else "error", "data": res}

@app.post("/api/pentest/scan/stop")
async def api_pentest_scan_stop():
    res = await pentest_engine.stop_scan()
    return {"status": "success" if res["success"] else "error", "data": res}

@app.get("/api/pentest/scan/results")
async def api_pentest_scan_results():
    res = await pentest_engine.get_scan_results()
    return {"status": "success", "data": res}

@app.post("/api/pentest/attack/deauth")
async def api_pentest_deauth(request: Request):
    body = await request.json()
    bssid = body.get("bssid")
    client = body.get("client")
    count = body.get("count", 10)
    interface = body.get("interface")
    
    if not bssid:
        return {"status": "error", "message": "BSSID required"}
        
    if client:
        res = await pentest_engine.attack_deauth_targeted(bssid, client, count, interface)
    else:
        res = await pentest_engine.attack_deauth_broadcast(bssid, count, interface)
        
    return {"status": "success" if res["success"] else "error", "data": res}

@app.post("/api/pentest/attack/stop")
async def api_pentest_attack_stop():
    res = await pentest_engine.stop_attack()
    return {"status": "success" if res["success"] else "error", "data": res}

@app.websocket("/ws/pentest/scan")
async def ws_pentest_scan(websocket: WebSocket):
    """
    WebSocket endpoint for real-time airodump-ng scanning.
    Flow: Frontend sends params → Backend starts airodump-ng subprocess →
    Reads CSV every 2s → Sends parsed JSON to frontend via WebSocket.
    """
    await websocket.accept()
    try:
        params_data = await websocket.receive_text()
        params = json.loads(params_data)

        async for update in pentest_engine.stream_scan(
            interface=params.get("interface"),
            channel=params.get("channel"),
            bssid=params.get("bssid"),
            essid=params.get("essid"),
            interval=2.0
        ):
            await websocket.send_json(update)
    except WebSocketDisconnect:
        logger.info("Pentest scan WebSocket disconnected")
    except Exception as e:
        logger.error(f"Pentest WS Error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        await pentest_engine.stop_stream()
        try:
            await websocket.close()
        except:
            pass

@app.websocket("/ws/terminal")
async def ws_terminal(websocket: WebSocket):
    """
    WebSocket endpoint for interactive web terminal using TerminalSessionManager.
    """
    await websocket.accept()
    session_id, session = await terminal_manager.create_session()

    try:
        # Receive initial config (terminal size)
        try:
            config_data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            config = json.loads(config_data)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            config = {}

        cols = config.get("cols", 220)
        rows = config.get("rows", 50)

        result = await session.start(cols=cols, rows=rows, require_root=True)
        # Compatibility: frontend might expect 'started' or 'init'
        await websocket.send_json({"type": "started", "data": result})

        if not result["success"]:
            return

        # Background task: read process output -> send to browser
        async def send_output():
            async for chunk in session.output_stream():
                try:
                    await websocket.send_bytes(chunk)
                except Exception:
                    break

        output_task = asyncio.create_task(send_output())

        # Main loop: receive browser input -> write to process
        while session.is_running:
            try:
                msg = await asyncio.wait_for(websocket.receive(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if msg["type"] == "websocket.disconnect":
                break

            if "bytes" in msg and msg["bytes"]:
                await session.write(msg["bytes"])

            elif "text" in msg and msg["text"]:
                try:
                    data = json.loads(msg["text"])
                    if data.get("type") == "input":
                        await session.write(data["data"].encode())
                    elif data.get("type") == "resize":
                        await session.resize(
                            data.get("cols", cols),
                            data.get("rows", rows)
                        )
                except json.JSONDecodeError:
                    # Fallback for raw text input if any
                    await session.write(msg["text"].encode())

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Terminal WS Error: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
    finally:
        if 'output_task' in locals():
            output_task.cancel()
        await terminal_manager.destroy_session(session_id)
        try:
            await websocket.close()
        except:
            pass

@app.get("/api/export/json")
async def export_json():
    data = await get_latest_full_scan()
    return Response(content=json.dumps(data, indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=scan_report.json"})

@app.get("/api/export/csv")
async def export_csv():
    import csv
    import io
    data = await get_latest_full_scan()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP Address", "MAC Address", "Hostname", "Vendor", "OS", "Risk Score", "Open Ports", "Vulnerabilities Count"])
    for d in data:
        ports_str = ", ".join(map(str, d.get("ports", [])))
        vuln_count = len(d.get("vulnerabilities", []))
        writer.writerow([d.get("ip"), d.get("mac"), d.get("hostname"), d.get("vendor"), d.get("os"), d.get("risk_score"), ports_str, vuln_count])
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=scan_report.csv"})

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True, loop="asyncio", reload_excludes=["*.db", "*.db-journal", "*.db-wal", "*.db-shm", "config.json"])
