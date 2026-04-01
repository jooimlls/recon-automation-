from django.urls import include, path


urlpatterns = [
    path("", include("reconweb.urls")),
]
