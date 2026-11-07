import os, json, threading, time, uuid
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from engine import create_account
from rarity import get_rarity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

app = FastAPI(title="XORA Mini")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── State global job (in-memory, cukup untuk 1 user) ──
JOBS = {}
LOCK = threading.Lock()

# ── Model ──
class GenReq(BaseModel):
    count: int = 10
    region: str = "ID"
    threads: int = 20
    name_prefix: str = "XORA"

# ── Helper ──
def save_result(acc, rarity):
    folder = os.path.join(DATA_DIR, "accounts", rarity, acc["region"])
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{acc['account_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({**acc, "rarity": rarity}, f, indent=2)

def worker(job_id, region, name_prefix, stop_flag):
    job = JOBS[job_id]
    while not stop_flag.is_set():
        with LOCK:
            if job["ok"] >= job["target"]:
                break

        acc = create_account(region)
        if not acc or acc.get("account_id") in (None, "", "N/A"):
            time.sleep(0.05)
            continue

        rarity, pattern = get_rarity(acc["account_id"])
        acc["rarity"] = rarity
        acc["pattern"] = pattern
        save_result(acc, rarity)

        with LOCK:
            job["ok"] += 1
            job["rarity_counts"][rarity] = job["rarity_counts"].get(rarity, 0) + 1
            job["log"].append({
                "id": acc["account_id"],
                "uid": acc["uid"],
                "pw": acc["password"],
                "name": acc["name"],
                "rarity": rarity,
                "pattern": pattern,
            })
            job["log"] = job["log"][-200:]  # simpan 200 terakhir

    with LOCK:
        job["status"] = "done"
        job["finished_at"] = datetime.now().isoformat()

def run_job(job_id, req: GenReq):
    stop_flag = threading.Event()
    JOBS[job_id]["stop_flag"] = stop_flag
    threads = []
    for _ in range(req.threads):
        t = threading.Thread(target=worker, args=(job_id, req.region, req.name_prefix, stop_flag), daemon=True)
        t.start()
        threads.append(t)

# ── Endpoints ──
@app.get("/api/health")
def health():
    return {"ok": True}

@app.post("/api/generate")
def start_generate(req: GenReq, bg: BackgroundTasks):
    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {
        "id": job_id,
        "target": req.count,
        "ok": 0,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "finished_at": None,
        "rarity_counts": {},
        "log": [],
        "stop_flag": None,
    }
    bg.add_task(run_job, job_id, req)
    return {"job_id": job_id}

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    j = JOBS[job_id]
    return {
        "id": j["id"],
        "target": j["target"],
        "ok": j["ok"],
        "status": j["status"],
        "started_at": j["started_at"],
        "finished_at": j["finished_at"],
        "rarity_counts": j["rarity_counts"],
        "log": j["log"],
    }

@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    sf = JOBS[job_id].get("stop_flag")
    if sf: sf.set()
    JOBS[job_id]["status"] = "stopped"
    return {"ok": True}

@app.get("/api/accounts")
def list_accounts(rarity: Optional[str] = None, region: Optional[str] = None, limit: int = 100):
    base = os.path.join(DATA_DIR, "accounts")
    if not os.path.exists(base):
        return {"total": 0, "items": []}
    items = []
    rarities = [rarity] if rarity else os.listdir(base)
    for r in rarities:
        rp = os.path.join(base, r)
        if not os.path.isdir(rp): continue
        regions = [region] if region else os.listdir(rp)
        for reg in regions:
            regp = os.path.join(rp, reg)
            if not os.path.isdir(regp): continue
            for f in os.listdir(regp):
                if not f.endswith(".json"): continue
                try:
                    with open(os.path.join(regp, f), encoding="utf-8") as fh:
                        items.append(json.load(fh))
                except Exception:
                    pass
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"total": len(items), "items": items[:limit]}

@app.get("/api/stats")
def stats():
    base = os.path.join(DATA_DIR, "accounts")
    out = {}
    if os.path.exists(base):
        for r in os.listdir(base):
            rp = os.path.join(base, r)
            if not os.path.isdir(rp): continue
            cnt = 0
            for reg in os.listdir(rp):
                regp = os.path.join(rp, reg)
                if os.path.isdir(regp):
                    cnt += len([f for f in os.listdir(regp) if f.endswith(".json")])
            out[r] = cnt
    return out

# ── Serve frontend (opsional, kalau mau 1 port) ──
FRONTEND = os.path.join(BASE_DIR, "..", "frontend")
if os.path.exists(FRONTEND):
    @app.get("/")
    def root():
        return FileResponse(os.path.join(FRONTEND, "index.html"))
