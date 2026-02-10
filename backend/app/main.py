import asyncio
from fastapi import FastAPI, WebSocketDisconnect
from app.api.ingest import router as ingest_router
from app.api.alerts import router as alerts_router
from app.api.logs import router as logs_router
from app.api.ml import router as ml_router, run_training
from app.api.incidents import router as incidents_router
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket 
from app.ws.alerts import manager
from app.ml.anomaly import anomaly_model

app = FastAPI(title="SentinelAI SOC Backend")

app.include_router(ingest_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(ml_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def _periodic_ml_train():
    while True:
        try:
            await run_training(7, 1000)
        except Exception as exc:
            print(f"[ml] periodic training failed: {exc}")
        await asyncio.sleep(6 * 60 * 60)


@app.on_event("startup")
async def startup_event():
    if not anomaly_model.trained:
        try:
            await run_training(7, 1000)
        except Exception as exc:
            print(f"[ml] initial training failed: {exc}")
    asyncio.create_task(_periodic_ml_train())


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
def root():
    return {"status": "SentinelAI backend running"}
