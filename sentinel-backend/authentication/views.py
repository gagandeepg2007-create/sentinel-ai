import uuid
import requests
import datetime
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from bson import ObjectId
from collections import Counter

from .models import SecurityLog
from .serializers import (
    SentinelTokenObtainPairSerializer, 
    UserRegistrationSerializer, 
    SecurityLogSerializer
)
from .mongo_models import RawLogDocument


class SentinelTokenObtainView(TokenObtainPairView):
    """
    API View Endpoint that checks login details and issues role-aware JWT pairs.
    """
    serializer_class = SentinelTokenObtainPairSerializer


class UserRegistrationView(APIView):
    """
    API View Endpoint that handles provisioning brand new analyst accounts.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "status": "success",
                "message": "Security operator profile provisioned cleanly.",
                "operator_id": str(user.id)
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SecurityLogListView(APIView):
    """
    Unified API View Endpoint handling route mapping topography for /api/security/logs/.
    - GET: Serves real-time relational security log metrics OR targeted MongoDB sync lookups.
    - POST: Accepts file streams (.log, .txt), parses them, saves to MongoDB, 
            and securely handshakes with the external FastAPI AI Compute Layer.
    """
    permission_classes = [permissions.AllowAny]
    parser_classes = [MultiPartParser, FormParser] 

    def get(self, request):
        """
        Serves telemetry requests. 
        If a 'uuid' query parameter is present, it returns the complete AI-enriched document 
        from MongoDB matching the structural schema layout required by the Next.js frontend. 
        Otherwise, it defaults back to standard relational database items.
        """
        target_uuid = request.query_params.get('uuid') or request.GET.get('uuid')

        # If the Next.js frontend is actively polling/syncing for a specific file upload session token:
        if target_uuid:
            try:
                # Optimized MongoDB lookup utilizing RawLogDocument abstraction layer mesh
                collection = RawLogDocument.get_collection()
                document = collection.find_one({
                    "$or": [
                        {"ingestion_uuid": target_uuid},
                        {"ingestion_id": target_uuid}
                    ]
                })

                if not document:
                    return Response(
                        {"error": f"Telemetry bundle/registry token session '{target_uuid}' not found inside MongoDB matrix."}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
                    
                # Cleanly format and sanitize MongoDB ObjectIds to prevent JSON parsing breaks
                if "_id" in document:
                    document["_id"] = str(document["_id"])
                
                # Map payload exactly to match the real-time inline AI stream interface requirements
                response_data = {
                    "ingestion_uuid": document.get("ingestion_uuid") or document.get("ingestion_id"),
                    "records": document.get("records", [])
                }
                
                return Response(response_data, status=status.HTTP_200_OK)

            except Exception as mongo_err:
                return Response(
                    {"error": f"NoSQL Cluster Pipeline Sync Fault: {str(mongo_err)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        # Default Behavior: Serve standard relational dashboard panel elements if no UUID parameter is specified
        logs = SecurityLog.objects.all().order_by('-timestamp')[:10]
        serializer = SecurityLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        """
        Processes multipart raw log document stream uploads, commits them to 
        MongoDB NoSQL storage, and fires a background trigger payload to the FastAPI engine.
        """
        if 'file' not in request.FILES:
            return Response(
                {"error": "Incomplete Payload: No log stream file attached."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        uploaded_file = request.FILES['file']
        
        if uploaded_file.size > 5 * 1024 * 1024:
            return Response(
                {"error": "Payload Restriction: Log streams must remain below 5MB threshold."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            raw_content = uploaded_file.read().decode('utf-8')
            log_lines = [line.strip() for line in raw_content.splitlines() if line.strip()]
            
            if not log_lines:
                return Response(
                    {"error": "Empty Stream: No readable data parsed within text boundaries."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            operator_email = "gagan@sentinel.ai"
            if request.user and request.user.is_authenticated:
                operator_email = request.user.email
            elif hasattr(request, 'user') and hasattr(request.user, 'email') and request.user.email:
                operator_email = request.user.email

            # Pipeline handoff to the non-relational MongoDB storage mesh
            mongo_obj_id, ingestion_uuid = RawLogDocument.ingest_raw_batch(
                operator_email=operator_email,
                filename=uploaded_file.name,
                log_entries=log_lines
            )

            # Inter-Service Communication Webhook Trigger to FastAPI node on port 8005
            FASTAPI_TRIGGER_URL = "http://127.0.0.1:8005/api/v1/inference/trigger/"
            trigger_payload = {"ingestion_id": ingestion_uuid}
            
            ai_service_status = "TRIGGER_FAILED"
            try:
                response = requests.post(FASTAPI_TRIGGER_URL, json=trigger_payload, timeout=3.0)
                if response.status_code == 200:
                    ai_service_status = "QUEUED_FOR_AI_INFERENCE"
                else:
                    ai_service_status = f"FASTAPI_ERROR_STATUS_{response.status_code}"
            except requests.exceptions.RequestException as e:
                ai_service_status = f"FASTAPI_OFFLINE_OR_TIMEOUT: {str(e)}"

            # Fetch the complete document from MongoDB to populate the immediate return payload
            collection = RawLogDocument.get_collection()
            saved_document = collection.find_one({
                "$or": [
                    {"ingestion_id": ingestion_uuid},
                    {"ingestion_uuid": ingestion_uuid}
                ]
            })
            
            records_data = saved_document.get("records", []) if saved_document else []
            entry_count_val = saved_document.get("entry_count", len(log_lines)) if saved_document else len(log_lines)

            return Response({
                "status": "INGESTION_COMPLETE",
                "message": f"Successfully cataloged {len(log_lines)} records to NoSQL grid.",
                "ingestion_uuid": ingestion_uuid,      
                "ingestion_id": ingestion_uuid,        
                "target_ref": str(mongo_obj_id),       
                "record_count": len(log_lines),
                "entry_count": entry_count_val,
                "ai_engine_status": ai_service_status, 
                "records": records_data                
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response(
                {"error": f"Internal Processing System Failure: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecurityDashboardStatsView(APIView):
    """
    API Endpoint that aggregates polymorphic MongoDB telemetry logs
    to serve high-level chart metrics and KPI analytics cards.
    """
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            collection = RawLogDocument.get_collection()
            
            # Fetch all documents to parse sub-record arrays
            # For massive enterprise files, use a native MongoDB $unwind aggregation pipeline
            cursor = collection.find({}, {"records": 1})
            
            total_processed_logs = 0
            critical_threat_count = 0
            anomaly_count = 0
            benign_count = 0
            
            ip_distribution = Counter()
            timeline_data = {}

            for doc in cursor:
                records = doc.get("records", [])
                for record in records:
                    total_processed_logs += 1
                    score = record.get("anomaly_score", 0)
                    source_ip = record.get("source_ip", "UNKNOWN")
                    timestamp = record.get("timestamp", "")[:10] # Extract YYYY-MM-DD
                    
                    # 1. Aggregate Threat Categories
                    if score >= 90:
                        critical_threat_count += 1
                    elif score >= 50:
                        anomaly_count += 1
                    else:
                        benign_count += 1
                        
                    # 2. Track Top Attacking/Source IPs
                    if score >= 50:
                        ip_distribution[source_ip] += 1
                        
                    # 3. Bucket Volume over Timeline
                    if timestamp:
                        if timestamp not in timeline_data:
                            timeline_data[timestamp] = {"timestamp": timestamp, "threats": 0, "total": 0}
                        timeline_data[timestamp]["total"] += 1
                        if score >= 50:
                            timeline_data[timestamp]["threats"] += 1

            # Format top malicious IP list for bar charts
            top_ips = [{"ip": ip, "count": count} for ip, count in ip_distribution.most_common(5)]
            
            # Format chronological trend data sorted by date
            chart_timeline = sorted(timeline_data.values(), key=lambda x: x["timestamp"])

            return Response({
                "status": "success",
                "kpis": {
                    "total_logs": total_processed_logs,
                    "critical_threats": critical_threat_count,
                    "anomalies_detected": anomaly_count,
                    "clean_events": benign_count,
                    "overall_risk_index": round((critical_threat_count + anomaly_count) / max(total_processed_logs, 1) * 100, 2) if total_processed_logs > 0 else 0
                },
                "top_malicious_ips": top_ips,
                "threat_timeline": chart_timeline
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to compute operational intelligence: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AutomatedContainmentView(APIView):
    """
    PHASE 5: Active Defense & Incident Response Webhook Trigger.
    When the AI flags a critical threat, the frontend calls this endpoint 
    to simulate an automated firewall block and dispatch a SOC alert.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            source_ip = request.data.get('source_ip', 'UNKNOWN_IP')
            threat_score = request.data.get('threat_score', 100)
            threat_type = request.data.get('threat_type', 'CRITICAL_ANOMALY')

            # 1. Simulate the Webhook Payload Generation
            webhook_payload = {
                "alert": "VIGIL-X AUTOMATED CONTAINMENT INITIATED",
                "action_taken": "IP_BLACKLISTED_AT_EDGE_FIREWALL",
                "target_ip": source_ip,
                "confidence_score": f"{threat_score}%",
                "vector": threat_type,
                "timestamp": datetime.datetime.now().isoformat()
            }

            # In a production enterprise setting, you would send this to Slack/Discord:
            # requests.post("https://discord.com/api/webhooks/your-webhook-id", json=webhook_payload)
            
            # For our PBL architecture demonstration, we will log it directly to the Django console
            print("\n" + "="*60)
            print("🚨 [VIGIL-X IPS] ACTIVE MITIGATION PROTOCOL ENGAGED 🚨")
            print(f"-> Threat Vector Isolated: {threat_type}")
            print(f"-> Action: Blacklisting Origin IP [ {source_ip} ]")
            print(f"-> Webhook Notification Dispatched to SOC Team.")
            print("="*60 + "\n")

            return Response({
                "status": "CONTAINMENT_SUCCESS",
                "message": f"IP {source_ip} successfully blocked. Webhook dispatched.",
                "action_log": webhook_payload
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Failed to execute containment protocol: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Aliased endpoint assignments preserving routing topology signatures
LogIngestionUploadView = SecurityLogListView
LogIngestionView = SecurityLogListView