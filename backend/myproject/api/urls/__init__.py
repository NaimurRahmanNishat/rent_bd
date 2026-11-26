# api/urls/__init__.py
# account/urls/__init__.py
from django.urls import path, include
from api.health_check_view import health_check

urlpatterns = [
    path('health/', health_check),
]