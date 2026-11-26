# account/health_check_view.py
from django.db import connection
from django.core.cache import cache
from django.http import JsonResponse


def health_check(request):
    status = {
        "status": "ok",
        "database": "unknown",
        "cache": "unknown",
    }

    http_status = 200

    # Check PostgreSQL connection
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

        status["database"] = "ok"

    except Exception:
        status["database"] = "error"
        status["status"] = "error"
        http_status = 503

    # Check Redis cache
    try:
        cache.set(
            "health_check_ping",
            "pong",
            timeout=5,
        )

        cache_status = (
            cache.get("health_check_ping") == "pong"
        )

        status["cache"] = "ok" if cache_status else "error"

        if not cache_status:
            status["status"] = "error"
            http_status = 503

    except Exception:
        status["cache"] = "error"
        status["status"] = "error"
        http_status = 503

    return JsonResponse(status, status=http_status)

