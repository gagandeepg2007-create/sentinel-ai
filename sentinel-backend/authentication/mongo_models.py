import re
import uuid
import datetime
from django.conf import settings

# Robust MongoDB integration module validation hook
try:
    from sentinel_core.settings import mongo_db
except ImportError:
    try:
        from sentinel_core.db import mongo_db
    except ImportError:
        # Emergency local cluster fallback layout if reference pointers migrate during testing
        from pymongo import MongoClient
        client = MongoClient(getattr(settings, 'MONGO_URI', 'mongodb://localhost:27017/'))
        mongo_db = client[getattr(settings, 'MONGO_DB_NAME', 'sentinel_raw_telemetry')]

class RawLogDocument:
    """
    Data Access Object (DAO) interfacing directly with the MongoDB 'raw_syslogs' collection.
    Handles both high-velocity structured standard SIEM inputs and flexible key-value paired log formats.
    """
    collection_name = 'raw_syslogs'

    # Format 1: Enterprise Standard SIEM Regular Expression Tokenizer Engine
    # Matches: YYYY-MM-DD HH:MM:SS [SEVERITY] IP: <ip> PORT: <port> METHOD: <method> STATUS: <status> MSG: <msg>
    LOG_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<severity>\w+)\]\s+'
        r'IP:\s+(?P<source_ip>[\d\.]+)\s+'
        r'PORT:\s+(?P<target_port>\d+)\s+'
        r'METHOD:\s+(?P<http_method>\w+)\s+'
        r'STATUS:\s+(?P<http_status>\d+)\s+'
        r'MSG:\s+(?P<message>.+)$'
    )

    @staticmethod
    def get_collection():
        """
        Dynamically extracts the direct PyMongo collection instance, raising explicit 
        infrastructure trace alerts if the background database socket drops offline.
        """
        if mongo_db is None:
            raise ConnectionError("MongoDB cluster handle is offline or uninitialized.")
        return mongo_db[RawLogDocument.collection_name]

    @classmethod
    def parse_line(cls, line_text):
        """
        Dual-mode parsing utility. Attempts to match standard strict formats first.
        Falls back to deep regular expression parameter hunting if lines contain unaligned fields.
        """
        # Strategy A: Check strict corporate SIEM match layout
        match = cls.LOG_PATTERN.match(line_text)
        if match:
            data = match.groupdict()
            try:
                data['target_port'] = int(data['target_port'])
                data['http_status'] = int(data['http_status'])
            except ValueError:
                pass
            data['parsed_successfully'] = True
            return data

        # Strategy B: Dynamic key-value processing lookup fallback (Fixes 'malicious_traffic.log')
        record = {
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "severity": "INFO",
            "source_ip": "0.0.0.0",
            "target_port": 80,
            "http_method": "GET",
            "http_status": 200,
            "message": line_text,
            "parsed_successfully": False
        }

        try:
            # 1. Isolate text-marker severity rules
            for level in ["INFO", "WARNING", "CRITICAL"]:
                if level in line_text:
                    record["severity"] = level
                    break

            # 2. Extract dynamic telemetry assignments via isolated key regex patterns
            status_match = re.search(r'http_status=(\d+)', line_text)
            port_match = re.search(r'target_port=(\d+)', line_text)
            method_match = re.search(r'http_method=([A-Z]+)', line_text)
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line_text)

            if status_match:
                record["http_status"] = int(status_match.group(1))
            if port_match:
                record["target_port"] = int(port_match.group(1))
            if method_match:
                record["http_method"] = method_match.group(1)
            if ip_match:
                record["source_ip"] = ip_match.group(0)

            # Mark safe if at least the core status codes or IPs were discovered
            if status_match or port_match or ip_match:
                record["parsed_successfully"] = True

        except Exception:
            record["parsed_successfully"] = False

        return record

    @classmethod
    def ingest_raw_batch(cls, operator_email, filename, log_entries):
        """
        Transforms arrays of unstructured log arguments, encapsulates them inside a uniform 
        corporate envelope layout with unique state tracking ids, and commits them to NoSQL storage.
        """
        collection = cls.get_collection()
        ingestion_uuid = str(uuid.uuid4())
        
        # Stream-parse every text element using our updated dual-parsing method
        processed_records = [cls.parse_line(line) for line in log_entries]

        # Consolidated schema architecture combining tracking parameters with sub-documents
        document = {
            "ingestion_id": ingestion_uuid,
            "uploaded_by": operator_email,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "source_file": filename,
            "entry_count": len(log_entries),
            "records": processed_records,
            "processing_status": "PENDING_AI_INFERENCE"
        }
        
        result = collection.insert_one(document)
        return str(result.inserted_id), ingestion_uuid
    
    @classmethod
    def fetch_recent_ingestions(cls, limit=5):
        """
        Retrieves structural metadata indexes from MongoDB, excluding dense arrays
        to ensure instantaneous network throughput calculations across user dashboards.
        """
        collection = cls.get_collection()
        # Keep this optimized for the main overview dashboard grid
        return list(collection.find({}, {"records": 0}).sort("timestamp", -1).limit(limit))

    @classmethod
    def fetch_single_ingestion_details(cls, ingestion_uuid):
        """
        Retrieves a complete ingestion document matching a specific UUID registry token,
        including all nested telemetry lines and AI threat scoring matrices.
        """
        collection = cls.get_collection()
        # Find explicitly by UUID and DO NOT strip out the {"records"} field
        return collection.find_one({"ingestion_uuid": ingestion_uuid})