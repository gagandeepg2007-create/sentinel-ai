from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from .config import db, logger
from .models import ThreatInferenceEngine

app = FastAPI(title="VIGIL-X AI Compute Gateway", version="3.0.0")

class IngestionTriggerRequest(BaseModel):
    ingestion_id: str

def execute_async_threat_inference(ingestion_id: str):
    try:
        collection = db['raw_syslogs']
        doc = collection.find_one({"ingestion_id": ingestion_id})
        
        if not doc:
            logger.error(f"[-] Record package tracking token not found: {ingestion_id}")
            return

        records = doc.get('records', [])
        if not records:
            collection.update_one({"ingestion_id": ingestion_id}, {"$set": {"processing_status": "COMPLETED_EMPTY"}})
            return

        logger.info(f"[*] Processing thread active on log batch: {ingestion_id}")
        analyzed_records = ThreatInferenceEngine.analyze_batch(records)

        total_anomalies = sum(1 for r in analyzed_records if r.get('is_anomaly', False))
        max_risk_detected = max((r.get('anomaly_score', 0) for r in analyzed_records), default=0)

        collection.update_one(
            {"ingestion_id": ingestion_id},
            {
                "$set": {
                    "records": analyzed_records,
                    "processing_status": "COMPLETED_AI_INFERENCE",
                    "summary_metrics": {
                        "anomalies_detected": total_anomalies,
                        "highest_risk_score": max_risk_detected,
                        "threat_level": "CRITICAL" if max_risk_detected > 75 else "ELEVATED" if total_anomalies > 0 else "NOMINAL"
                    }
                }
            }
        )
        logger.info(f"[+] Successfully saved AI thread analytics back to document: {ingestion_id}")
    except Exception as e:
        logger.error(f"[!] Processing worker failed on ingestion block: {str(e)}")

@app.post("/api/v1/inference/trigger/")
async def trigger_ingestion_analysis(payload: IngestionTriggerRequest, background_tasks: BackgroundTasks):
    doc_exists = db['raw_syslogs'].find_one({"ingestion_id": payload.ingestion_id}, {"_id": 1})
    if not doc_exists:
        raise HTTPException(status_code=404, detail="Requested ingestion token does not match active records.")

    db['raw_syslogs'].update_one({"ingestion_id": payload.ingestion_id}, {"$set": {"processing_status": "PROCESSING_AI_INFERENCE"}})
    background_tasks.add_task(execute_async_threat_inference, payload.ingestion_id)
    return {"status": "QUEUED", "ingestion_id": payload.ingestion_id}