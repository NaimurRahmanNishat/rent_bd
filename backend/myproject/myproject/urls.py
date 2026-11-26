# myproject/urls.py
from decouple import config
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

admin_path = config("ADMIN_URL", default="admin/").strip("/")

urlpatterns = [
    path(f"{admin_path}/", admin.site.urls),
    path('api/', include('api.urls')),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)