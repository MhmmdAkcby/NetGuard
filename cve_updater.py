import aiosqlite
import json
import logging
import httpx
from datetime import datetime
from database import DB_NAME

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def update_cve_database():
    """Fetches recent CVEs from NVD and updates local cache."""
    try:
        logger.info("Checking for CVE updates...")
        async with httpx.AsyncClient() as client:
            # Fetch last 24h updates
            response = await client.get(NVD_API_URL, params={"resultsPerPage": 100})
            if response.status_code == 200:
                data = response.json()
                await process_nvd_data(data)
                logger.info("CVE database updated successfully.")
            else:
                logger.error(f"NVD API error: {response.status_code}")
    except Exception as e:
        logger.error(f"CVE update failed: {e}")

async def process_nvd_data(data):
    """
    Parses NVD JSON v2.0 and upserts into cve_feed table.
    """
    async with aiosqlite.connect(DB_NAME) as conn:
        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            desc = cve.get("descriptions", [{}])[0].get("value", "")
            published = cve.get("published", "")
            
            # Severity and CVSS
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", [{}]))[0]
            cvss_data = cvss_v3.get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            
            # Affected products (Simplified for keyword matching)
            configs = cve.get("configurations", [])
            affected = json.dumps(configs)
            
            await conn.execute('''
                INSERT OR REPLACE INTO cve_feed (cve_id, severity, cvss, description, affected_products, published_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cve_id, severity, score, desc, affected, published))
            
        await conn.commit()
        logger.info(f"Processed {len(vulnerabilities)} CVEs.")

async def get_cve_stats():
    """Returns count of CVEs by severity."""
    async with aiosqlite.connect(DB_NAME) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute("SELECT severity, COUNT(*) as count FROM cve_feed GROUP BY severity") as cursor:
            rows = await cursor.fetchall()
            return {r['severity']: r['count'] for r in rows}
