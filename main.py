import os
import logging
from typing import Any, Optional, List, Dict, Tuple

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from dotenv import load_dotenv

import psycopg2
from psycopg2.extras import RealDictCursor, Json
import redis
import requests

from s3_utils import build_object_key, presign_put_object

# Load env
load_dotenv("/home/ubuntu/qsight-api/.env")

# Logging (systemd/journalctl로 확인 가능)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [qsight] %(message)s",
)
logger = logging.getLogger("qsight")

app = FastAPI(title="Qsight API", version="0.4.1")

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = (os.getenv("VT_BASE_URL") or "https://www.virustotal.com/api/v3").rstrip("/")


# -----------------------------
# Helpers (DB/Redis)
# -----------------------------
def get_pg_conn():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "127.0.0.1"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "qsight_db"),
        user=os.getenv("POSTGRES_USER", "qsight_app"),
        password=os.getenv("POSTGRES_PASSWORD", ""),
        cursor_factory=RealDictCursor,
    )

def get_redis_client():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        decode_responses=True,
    )

def serialize_row(row: Optional[Dict[str, Any]]):
    if row is None:
        return None
    return dict(row)


# -----------------------------
# Helpers (VirusTotal)
# -----------------------------
def vt_lookup_sha256(sha256: str) -> Tuple[Optional[dict], int, Optional[str]]:
    """
    Returns: (stats | None, http_status, error_text)
    - 200: stats dict returned
    - 404: None (no record)
    - 429: None (rate limited)
    - other: None (error)
    """
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VT_API_KEY_not_set")

    url = f"{VT_BASE_URL}/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=12)
    except requests.RequestException as e:
        return None, 0, f"request_exception:{e}"

    if r.status_code == 200:
        data = r.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        return stats, 200, None

    # no record
    if r.status_code == 404:
        return None, 404, None

    # rate limited
    if r.status_code == 429:
        return None, 429, (r.text[:300] if r.text else "rate_limited")

    # other errors
    return None, r.status_code, (r.text[:300] if r.text else "unknown_error")

def map_vt_stats_to_static_result(stats: Optional[dict]) -> str:
    """
    요구사항: clean / malicious / unknown
    보수적으로 매핑:
      malicious > 0 => malicious
      suspicious > 0 => unknown
      (malicious==0 and suspicious==0 and (harmless>0 or undetected>0)) => clean
      그 외 => unknown
    """
    if stats is None:
        return "unknown"

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "unknown"
    if (harmless > 0 or undetected > 0) and malicious == 0 and suspicious == 0:
        return "clean"
    return "unknown"

def insert_vt_event(
    scan_id: str,
    sha256: str,
    vt_status: int,
    stats: Optional[dict],
    static_result: Optional[str],
    error: Optional[str],
):
    """vt_static 이벤트는 무조건 남겨서 디버깅 증거로 쓴다."""
    conn = get_pg_conn()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO scan_events (scan_id, event_type, extra) VALUES (%s,%s,%s);",
            (
                scan_id,
                "vt_static",
                Json(
                    {
                        "sha256": sha256,
                        "vt_status": vt_status,
                        "stats": stats,
                        "static_result": static_result,
                        "error": error,
                    }
                ),
            ),
        )
    conn.commit()
    conn.close()

def update_static_result(scan_id: str, static_result: str):
    conn = get_pg_conn()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE scans SET static_result=%s, updated_at=now() WHERE scan_id=%s;",
            (static_result, scan_id),
        )
    conn.commit()
    conn.close()


# -----------------------------
# Pydantic models
# -----------------------------
class ScanCreateRequest(BaseModel):
    employee_id: str
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    sha256: str = Field(..., min_length=64, max_length=64)
    source_type: str = "watcher"
    static_result: str = "unknown"
    dynamic_score: Optional[int] = None
    severity: str = "low"
    status: str = "queued"


class ScanEventCreateRequest(BaseModel):
    event_type: str
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    target: Optional[str] = None
    result: Optional[str] = None
    extra: Optional[dict] = None


class ScanReportUpsertRequest(BaseModel):
    llm_model: Optional[str] = None
    threat_score: Optional[int] = None
    summary: Optional[str] = None
    details: Optional[dict] = None


class UploadPresignRequest(BaseModel):
    org_id: str
    employee_id: str
    scan_id: str
    sha256: str = Field(..., min_length=64, max_length=64)
    file_name: str
    content_type: str = "application/octet-stream"


class UploadCompleteRequest(BaseModel):
    object_key: str


# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/health/deep")
def health_deep():
    pg_ok = False
    redis_ok = False
    pg_error = None
    redis_error = None

    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
        conn.close()
        pg_ok = True
    except Exception as e:
        pg_error = str(e)

    try:
        r = get_redis_client()
        redis_ok = (r.ping() is True)
    except Exception as e:
        redis_error = str(e)

    status = "ok" if (pg_ok and redis_ok) else "degraded"
    return {
        "status": status,
        "postgres": {"ok": pg_ok, "error": pg_error},
        "redis": {"ok": redis_ok, "error": redis_error},
    }


# -----------------------------
# S3 Upload
# -----------------------------
@app.post("/uploads/presign")
def uploads_presign(body: UploadPresignRequest):
    object_key = build_object_key(
        body.org_id, body.employee_id, body.scan_id, body.sha256, body.file_name
    )
    put_url = presign_put_object(object_key, body.content_type, expires_in=900)
    return {"ok": True, "put_url": put_url, "object_key": object_key, "expires_in": 900}


@app.post("/scans/{scan_id}/uploads/complete")
def uploads_complete(scan_id: str, body: UploadCompleteRequest):
    """
    업로드 완료 기록 + VT 정적 분석 자동 실행(로그+DB 이벤트로 증거 남김)
    """
    try:
        # scan 존재 + sha256
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT scan_id::text, sha256 FROM scans WHERE scan_id=%s;", (scan_id,))
            s = cur.fetchone()
            if not s:
                raise HTTPException(status_code=404, detail="scan_not_found")
            sha256 = s["sha256"]

            # s3_upload event
            cur.execute(
                """
                INSERT INTO scan_events (scan_id, event_type, extra)
                VALUES (%s, %s, %s)
                RETURNING id, scan_id::text, event_time, event_type, extra;
                """,
                (scan_id, "s3_upload", Json({"object_key": body.object_key})),
            )
            upload_ev = cur.fetchone()

        conn.commit()
        conn.close()

        # VT lookup (항상 로그 남김)
        logger.info(f"[VT] start scan_id={scan_id} sha256={sha256}")
        vt_stats, vt_status, vt_err = vt_lookup_sha256(sha256)

        static_result = None
        if vt_status in (200, 404):
            static_result = map_vt_stats_to_static_result(vt_stats)
            update_static_result(scan_id, static_result)

        # vt_static 이벤트는 무조건 남김(디버깅 증거)
        insert_vt_event(
            scan_id=scan_id,
            sha256=sha256,
            vt_status=vt_status,
            stats=vt_stats,
            static_result=static_result,
            error=vt_err,
        )

        logger.info(
            f"[VT] done scan_id={scan_id} sha256={sha256} vt_status={vt_status} static_result={static_result} err={vt_err}"
        )

        return {
            "ok": True,
            "upload_event": serialize_row(upload_ev),
            "vt_status": vt_status,
            "static_result": static_result or "unknown",
            "stats": vt_stats,
            "error": vt_err,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[uploads_complete] failed scan_id={scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"uploads_complete_failed: {e}")


# -----------------------------
# Manual VT refresh (retry)
# -----------------------------
@app.post("/scans/{scan_id}/static/vt-refresh")
def vt_refresh(scan_id: str):
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT scan_id::text, sha256 FROM scans WHERE scan_id=%s;", (scan_id,))
            s = cur.fetchone()
            if not s:
                raise HTTPException(status_code=404, detail="scan_not_found")
            sha256 = s["sha256"]
        conn.close()

        logger.info(f"[VT] manual start scan_id={scan_id} sha256={sha256}")
        vt_stats, vt_status, vt_err = vt_lookup_sha256(sha256)

        static_result = None
        if vt_status in (200, 404):
            static_result = map_vt_stats_to_static_result(vt_stats)
            update_static_result(scan_id, static_result)

        insert_vt_event(
            scan_id=scan_id,
            sha256=sha256,
            vt_status=vt_status,
            stats=vt_stats,
            static_result=static_result,
            error=vt_err,
        )

        logger.info(f"[VT] manual done scan_id={scan_id} vt_status={vt_status} static_result={static_result} err={vt_err}")

        return {"ok": True, "scan_id": scan_id, "vt_status": vt_status, "static_result": static_result or "unknown", "stats": vt_stats, "error": vt_err}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[vt_refresh] failed scan_id={scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"vt_refresh_failed: {e}")


# -----------------------------
# Scan endpoints
# -----------------------------
@app.post("/scans")
def create_scan(payload: ScanCreateRequest):
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (
                    employee_id, file_name, file_path, file_size, sha256,
                    source_type, static_result, dynamic_score, severity, status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING
                    scan_id::text,
                    employee_id,
                    file_name,
                    file_path,
                    file_size,
                    sha256,
                    source_type,
                    static_result,
                    dynamic_score,
                    severity,
                    status,
                    created_at,
                    updated_at
                ;
                """,
                (
                    payload.employee_id,
                    payload.file_name,
                    payload.file_path,
                    payload.file_size,
                    payload.sha256,
                    payload.source_type,
                    payload.static_result,
                    payload.dynamic_score,
                    payload.severity,
                    payload.status,
                ),
            )
            row = cur.fetchone()
        conn.commit()
        conn.close()

        try:
            r = get_redis_client()
            r.lpush("qsite:scan_queue", row["scan_id"])
        except Exception:
            pass

        return {"ok": True, "scan": serialize_row(row)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"create_scan_failed: {e}")


@app.post("/scans/{scan_id}/events")
def create_scan_event(scan_id: str, payload: ScanEventCreateRequest):
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT scan_id::text FROM scans WHERE scan_id=%s;", (scan_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="scan_not_found")

            cur.execute(
                """
                INSERT INTO scan_events (
                    scan_id, event_type, process_name, process_path, parent_process_name,
                    command_line, target, result, extra
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING
                    id, scan_id::text, event_time, event_type, process_name, process_path,
                    parent_process_name, command_line, target, result, extra
                ;
                """,
                (
                    scan_id,
                    payload.event_type,
                    payload.process_name,
                    payload.process_path,
                    payload.parent_process_name,
                    payload.command_line,
                    payload.target,
                    payload.result,
                    Json(payload.extra) if payload.extra is not None else None,
                ),
            )
            row = cur.fetchone()

            cur.execute(
                """
                UPDATE scans
                SET status = CASE WHEN status='queued' THEN 'analyzing' ELSE status END,
                    updated_at = now()
                WHERE scan_id=%s;
                """,
                (scan_id,),
            )

        conn.commit()
        conn.close()
        return {"ok": True, "event": serialize_row(row)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"create_scan_event_failed: {e}")


@app.post("/scans/{scan_id}/report")
def upsert_scan_report(scan_id: str, payload: ScanReportUpsertRequest):
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT scan_id::text FROM scans WHERE scan_id=%s;", (scan_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="scan_not_found")

            cur.execute(
                """
                INSERT INTO scan_reports (scan_id, llm_model, threat_score, summary, details)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (scan_id)
                DO UPDATE SET
                    llm_model = EXCLUDED.llm_model,
                    threat_score = EXCLUDED.threat_score,
                    summary = EXCLUDED.summary,
                    details = EXCLUDED.details,
                    created_at = now()
                RETURNING scan_id::text, llm_model, threat_score, summary, details, created_at;
                """,
                (
                    scan_id,
                    payload.llm_model,
                    payload.threat_score,
                    payload.summary,
                    Json(payload.details) if payload.details is not None else None,
                ),
            )
            row = cur.fetchone()

            cur.execute(
                "UPDATE scans SET status='done', updated_at=now() WHERE scan_id=%s;",
                (scan_id,),
            )

        conn.commit()
        conn.close()
        return {"ok": True, "report": serialize_row(row)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"upsert_scan_report_failed: {e}")


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    scan_id::text, employee_id, file_name, file_path, file_size, sha256,
                    source_type, static_result, dynamic_score, severity, status,
                    created_at, updated_at
                FROM scans
                WHERE scan_id=%s;
                """,
                (scan_id,),
            )
            scan = cur.fetchone()
            if not scan:
                raise HTTPException(status_code=404, detail="scan_not_found")

            cur.execute(
                """
                SELECT
                    id, scan_id::text, event_time, event_type, process_name, process_path,
                    parent_process_name, command_line, target, result, extra
                FROM scan_events
                WHERE scan_id=%s
                ORDER BY event_time ASC, id ASC;
                """,
                (scan_id,),
            )
            events = cur.fetchall()

            cur.execute(
                """
                SELECT
                    scan_id::text, llm_model, threat_score, summary, details, created_at
                FROM scan_reports
                WHERE scan_id=%s;
                """,
                (scan_id,),
            )
            report = cur.fetchone()

        conn.close()

        return {
            "ok": True,
            "scan": serialize_row(scan),
            "events": [serialize_row(e) for e in events],
            "report": serialize_row(report),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"get_scan_failed: {e}")




# --- Qsight: Dynamic Analysis Start (trigger) ---
@app.post("/scans/{scan_id}/dynamic/start")
def dynamic_start(scan_id: str):
    """
    프론트 '스캔 시작' 버튼용: 동적분석 시작 트리거 (현재는 stub).
    - scan 존재 확인
    - 최근 s3_upload 이벤트에서 object_key 추출
    - scans.status='analyzing' 업데이트
    - scan_events에 dynamic_start 이벤트 기록
    """
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT scan_id::text, status FROM scans WHERE scan_id=%s;", (scan_id,))
            scan = cur.fetchone()
            if not scan:
                raise HTTPException(status_code=404, detail="scan_not_found")

            cur.execute(
                """
                SELECT extra
                FROM scan_events
                WHERE scan_id=%s AND event_type='s3_upload'
                ORDER BY id DESC
                LIMIT 1;
                """,
                (scan_id,),
            )
            row = cur.fetchone()
            extra = (row or {}).get("extra")
            object_key = extra.get("object_key") if isinstance(extra, dict) else None
            if not object_key:
                raise HTTPException(status_code=400, detail="s3_object_key_not_found")

            cur.execute(
                "UPDATE scans SET status='analyzing', updated_at=now() WHERE scan_id=%s;",
                (scan_id,),
            )

            cur.execute(
                """
                INSERT INTO scan_events (scan_id, event_type, extra)
                VALUES (%s, %s, %s)
                RETURNING id, scan_id::text, event_time, event_type, extra;
                """,
                (scan_id, "dynamic_start", Json({"object_key": object_key, "runner": "stub"})),
            )
            start_ev = cur.fetchone()

        conn.commit()
        conn.close()

        return {"ok": True, "scan_id": scan_id, "status": "analyzing", "object_key": object_key, "runner": "stub", "event": serialize_row(start_ev)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dynamic_start_failed: {e}")
# --- end ---



@app.get("/dashboard/summary")
def dashboard_summary(
    days: int = Query(30, ge=1, le=365),
    employee_id: Optional[str] = None
):
    try:
        conn = get_pg_conn()
        with conn.cursor() as cur:
            where_clause = "WHERE created_at >= now() - (%s || ' days')::interval"
            params: List[Any] = [days]

            if employee_id:
                where_clause += " AND employee_id = %s"
                params.append(employee_id)

            cur.execute(
                f"""
                SELECT
                    COUNT(*)::int AS total_scans,
                    COALESCE(SUM(CASE WHEN static_result = 'unknown' THEN 1 ELSE 0 END),0)::int AS unknown_count,
                    COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),0)::int AS severity_high_count,
                    COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),0)::int AS severity_critical_count,
                    ROUND(COALESCE(AVG(dynamic_score),0)::numeric, 2) AS avg_dynamic_score
                FROM scans
                {where_clause};
                """,
                tuple(params),
            )
            summary = cur.fetchone()

            cur.execute(
                f"""
                SELECT
                    employee_id,
                    COUNT(*)::int AS scan_count,
                    COALESCE(SUM(CASE WHEN static_result = 'unknown' THEN 1 ELSE 0 END),0)::int AS unknown_count,
                    COALESCE(SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END),0)::int AS high_or_critical_count
                FROM scans
                {where_clause}
                GROUP BY employee_id
                ORDER BY scan_count DESC
                LIMIT 10;
                """,
                tuple(params),
            )
            top_employees = cur.fetchall()

        conn.close()

        return {
            "ok": True,
            "days": days,
            "employee_id": employee_id,
            "summary": serialize_row(summary),
            "top_employees": [serialize_row(r) for r in top_employees],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dashboard_summary_failed: {e}")
