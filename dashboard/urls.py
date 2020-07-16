from django.urls import path
from . import views

urlpatterns = [
    # localhost:8000/posts
    path('', views.dashboard),
    # localhost:8000/posts/<post_id>/delete
    path('<int:post_id>/delete', views.delete)
]