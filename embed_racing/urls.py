from django.urls import path
from . import views

app_name = 'embed_racing'  # Make sure this is defined

urlpatterns = [
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('generate_links/', views.generate_links, name='generate_links'),  # Ensure this exists
    path('track/<str:unique_id>.gif', views.track_embed, name='track_embed'),
]

