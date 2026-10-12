import time
import os
from playwright.sync_api import sync_playwright

PAGES = [
    ("soc-incident-workspace.png", "http://localhost:3000/"),
    ("risk-scorecard.png", "http://localhost:3000/dashboard/risk-scorecard"),
    ("fleet-management.png", "http://localhost:3000/dashboard/fleet"),
    ("threat-intel-yara.png", "http://localhost:3000/dashboard/threats"),
    ("remediation-plans.png", "http://localhost:3000/dashboard/plans"),
    ("compliance-matrix.png", "http://localhost:3000/dashboard/compliance"),
    ("vulnerability-scanner.png", "http://localhost:3000/dashboard/scanner"),
    ("onboarding-wizard.png", "http://localhost:3000/onboarding"),
    ("sign-in-screen.png", "http://localhost:3000/login"),
]

os.makedirs("docs/screenshots", exist_ok=True)
os.makedirs("public/screenshots", exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)
    page = browser.new_page(viewport={"width": 1600, "height": 900})
    
    for filename, url in PAGES:
        print(f"Capturing {filename} from {url}...")
        try:
            page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception as e:
            print(f"Navigation warning for {url}: {e}")
            
        time.sleep(2.5)  # allow animations, telemetry graphs, and state to render
        
        doc_path = os.path.join("docs", "screenshots", filename)
        pub_path = os.path.join("public", "screenshots", filename)
        
        page.screenshot(path=doc_path)
        page.screenshot(path=pub_path)
        print(f"  -> Saved {doc_path} and {pub_path}")

    browser.close()
    print("All 9 screenshots captured successfully!")
