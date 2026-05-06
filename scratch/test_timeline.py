import asyncio
from database import init_db, save_scan_results, get_history_timeline
from datetime import datetime, timedelta

async def test_timeline():
    await init_db()
    
    # Simulate some scans
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    
    # Device A: Online at 10:00 and 10:05
    results1 = [{"ip": "192.168.1.10", "mac": "AA:BB", "vendor": "V", "hostname": "HostA"}]
    # We need to manually manipulate scan_time for testing, but save_scan_results uses datetime.now()
    # So we'll just verify the function runs and returns data
    
    await save_scan_results(results1)
    
    timeline = await get_history_timeline(today)
    print(f"Timeline entries: {len(timeline)}")
    for entry in timeline:
        print(f"Device: {entry['label']} | Start: {entry['start']} | End: {entry['end']}")

if __name__ == "__main__":
    asyncio.run(test_timeline())
