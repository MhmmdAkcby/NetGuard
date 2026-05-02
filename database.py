import aiosqlite
import json
from datetime import datetime
import os
import logging

DB_NAME = "network_scans.db"
logger = logging.getLogger(__name__)

async def run_migrations(conn):
    """Schema Versioning: Tracks applied migrations in a dedicated table."""
    await conn.execute('''
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    migrations = [
        ("initial_schema", '''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time DATETIME, ip TEXT, mac TEXT, vendor TEXT, hostname TEXT,
                ports TEXT, os TEXT, services TEXT, risk_score INTEGER DEFAULT 0, vulnerabilities TEXT
            )
        '''),
        ("add_alerts_table", '''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME, severity TEXT, type TEXT, message TEXT, ip TEXT, resolved INTEGER DEFAULT 0
            )
        '''),
        ("add_health_table", '''
            CREATE TABLE IF NOT EXISTS network_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME, device_count INTEGER, network_score INTEGER, critical_alerts INTEGER
            )
        '''),
        ("add_vulnerabilities_table", '''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, port INTEGER, service_name TEXT, cve_id TEXT, severity TEXT, cvss REAL,
                description TEXT, recommendation TEXT, detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        '''),
        ("add_cve_feed_table", '''
            CREATE TABLE IF NOT EXISTS cve_feed (
                cve_id TEXT PRIMARY KEY, severity TEXT, cvss REAL, description TEXT,
                affected_products TEXT, published_date TEXT
            )
        '''),
        ("add_settings_table", '''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT
            )
        ''')
    ]

    for name, sql in migrations:
        async with conn.execute("SELECT id FROM migrations WHERE name = ?", (name,)) as cursor:
            row = await cursor.fetchone()
        if not row:
            try:
                await conn.execute(sql)
                await conn.execute("INSERT INTO migrations (name) VALUES (?)", (name,))
                logger.info(f"Migration applied: {name}")
            except Exception as e:
                logger.error(f"Migration failed: {name} - {e}")
    await conn.commit()

async def init_db():
    async with aiosqlite.connect(DB_NAME) as conn:
        await run_migrations(conn)

async def save_config(key, value):
    async with aiosqlite.connect(DB_NAME) as conn:
        await conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        await conn.commit()

async def get_config(key, default=None):
    async with aiosqlite.connect(DB_NAME) as conn:
        async with conn.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
        return row[0] if row else default

async def save_scan_results(results):
    try:
        async with aiosqlite.connect(DB_NAME) as conn:
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for d in results:
                await conn.execute('''
                    INSERT INTO scan_results (scan_time, ip, mac, vendor, hostname, ports, os, services, risk_score, vulnerabilities)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_time, d['ip'], d['mac'], d['vendor'], d['hostname'], 
                    json.dumps(d.get('ports', [])), d.get('os', 'Unknown'), json.dumps(d.get('services', {})), 
                    d.get('risk_score', 0), json.dumps(d.get('vulnerabilities', []))
                ))
                for v in d.get('vulnerabilities', []):
                    await conn.execute('''
                        INSERT INTO vulnerabilities (ip, service_name, cve_id, severity, cvss, description, recommendation)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (d['ip'], v['service'], v['cve'], v['severity'], v.get('cvss', 0.0), v['description'], v['recommendation']))
            await conn.commit()
    except Exception as e:
        logger.error(f"DB Save Error: {e}")

async def save_alert(severity, alert_type, message, ip=None):
    try:
        async with aiosqlite.connect(DB_NAME) as conn:
            await conn.execute('INSERT INTO alerts (timestamp, severity, type, message, ip) VALUES (?, ?, ?, ?, ?)',
                           (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), severity, alert_type, message, ip))
            await conn.commit()
    except Exception as e:
        logger.error(f"Alert Save Error: {e}")

async def get_alerts(limit=50, offset=0, severity=None, start_date=None, end_date=None):
    async with aiosqlite.connect(DB_NAME) as conn:
        conn.row_factory = aiosqlite.Row
        query = "SELECT * FROM alerts WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity)
        if start_date:
            query += " AND timestamp >= ?"
            count_query += " AND timestamp >= ?"
            params.append(start_date)
        if end_date:
            query += " AND timestamp <= ?"
            count_query += " AND timestamp <= ?"
            params.append(end_date)
        
        main_params = params + [limit, offset]
        
        async with conn.execute(query + " ORDER BY timestamp DESC LIMIT ? OFFSET ?", main_params) as cursor:
            rows = await cursor.fetchall()
        
        # Get total count for pagination
        async with conn.execute(count_query, params) as cursor:
            total = (await cursor.fetchone())[0]
            
        return {"items": [dict(r) for r in rows], "total": total}

def _safe_json_load(data, default):
    if data is None:
        return default
    try:
        return json.loads(data)
    except:
        return default

async def get_latest_full_scan():
    async with aiosqlite.connect(DB_NAME) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute('''
            SELECT * FROM scan_results WHERE scan_time = (
                SELECT scan_time FROM scan_results ORDER BY id DESC LIMIT 1
            )
        ''') as cursor:
            rows = await cursor.fetchall()
    
    res = []
    for r in rows:
        d = dict(r)
        d['ports'] = _safe_json_load(d.get('ports'), [])
        d['services'] = _safe_json_load(d.get('services'), {})
        d['vulnerabilities'] = _safe_json_load(d.get('vulnerabilities'), [])
        res.append(d)
    return res

async def save_network_health(count, score, criticals):
    async with aiosqlite.connect(DB_NAME) as conn:
        await conn.execute('INSERT INTO network_health (timestamp, device_count, network_score, critical_alerts) VALUES (?, ?, ?, ?)',
                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), count, score, criticals))
        await conn.commit()

async def get_latest_scans(limit=100, offset=0, ip=None, start_date=None, end_date=None):
    try:
        async with aiosqlite.connect(DB_NAME) as conn:
            conn.row_factory = aiosqlite.Row
            query = "SELECT * FROM scan_results WHERE 1=1"
            count_query = "SELECT COUNT(*) FROM scan_results WHERE 1=1"
            params = []
            if ip:
                query += " AND ip LIKE ?"
                count_query += " AND ip LIKE ?"
                params.append(f"%{ip}%")
            if start_date:
                query += " AND scan_time >= ?"
                count_query += " AND scan_time >= ?"
                params.append(start_date)
            if end_date:
                query += " AND scan_time <= ?"
                count_query += " AND scan_time <= ?"
                params.append(end_date)
                
            main_params = params + [limit, offset]
            
            async with conn.execute(query + " ORDER BY id DESC LIMIT ? OFFSET ?", main_params) as cursor:
                rows = await cursor.fetchall()
            
            # Get total count
            async with conn.execute(count_query, params) as cursor:
                total = (await cursor.fetchone())[0]
            
            results = []
            for row in rows:
                device = dict(row)
                device['ports'] = _safe_json_load(device.get('ports'), [])
                device['services'] = _safe_json_load(device.get('services'), {})
                device['vulnerabilities'] = _safe_json_load(device.get('vulnerabilities'), [])
                results.append(device)
            return {"items": results, "total": total}
    except Exception as e:
        logger.error(f"Database fetch error: {e}")
        return {"items": [], "total": 0}
