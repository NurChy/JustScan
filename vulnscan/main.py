from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import subprocess
import os
import json

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan")
async def scan(request: Request):
    data = await request.json()
    url = data.get("url")
    if not url:
        return JSONResponse(content={"error": "URL is required"}, status_code=400)

    os.environ["TARGET_URL"] = url
    result = subprocess.run(
        ["python", "vuln_scanner.py"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(__file__)
    )

    try:
        with open("results.json", "r") as f:
            vulnerabilities = json.load(f)

       
        import datetime
        history_path = os.path.join(os.path.dirname(__file__), "history.json")
        entry = {
            "url": url,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerability_count": len(vulnerabilities)
        }

        try:
            if os.path.exists(history_path):
                with open(history_path, "r") as f:
                    history = json.load(f)
            else:
                history = []

            history.insert(0, entry)
            with open(history_path, "w") as f:
                json.dump(history, f, indent=2)

        except Exception as e:
            print("Failed to write history:", e)

        return vulnerabilities

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/report")
def get_report():
    report_path = os.path.join(os.path.dirname(__file__), "vulnerability_report.html")
    if os.path.exists(report_path):
        return FileResponse(report_path, media_type="text/html", filename="vulnerability_report.html")
    return JSONResponse(content={"error": "Report not found"}, status_code=404)



@app.get("/history")
def get_history():
    history_path = os.path.join(os.path.dirname(__file__), "history.json")
    if os.path.exists(history_path):
        with open(history_path, "r") as f:
            return json.load(f)
    return []


@app.delete("/history/clear")
def clear_history():
    history_path = os.path.join(os.path.dirname(__file__), "history.json")
    if os.path.exists(history_path):
        with open(history_path, "w") as f:
            json.dump([], f)  
        return {"status": "history cleared"}
    return {"status": "no history file"}
