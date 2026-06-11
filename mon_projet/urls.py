from django.urls import path
from . import views

app_name = 'burp'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),

    # ── Scanner ──
    path('scanner/', views.scanner, name='scanner'),
    path('scanner/start/', views.start_scan, name='start_scan'),
    path('scanner/<str:scan_id>/status/', views.scan_status, name='scan_status'),
    path('scanner/<str:scan_id>/detail/', views.scan_detail, name='scan_detail'),
    path('scanner/<str:scan_id>/delete/', views.delete_scan, name='delete_scan'),

    # ── API Scanner ──
    path('api/scan/progress/<str:scan_id>/', views.scan_progress, name='scan_progress'),
    path('api/scan/results/<str:scan_id>/', views.scan_results, name='scan_results'),
    path('api/scans/recent/', views.recent_scans, name='recent_scans'),

    # ── Proxy ──
    path('proxy/', views.proxy, name='proxy'),
    path('proxy/intercept/toggle/', views.intercept_toggle, name='intercept_toggle'),  # ← MANQUAIT
    path('proxy/intercept/status/', views.intercept_status, name='intercept_status'),  # ← MANQUAIT
    path('proxy/intercept/', views.intercept_request, name='intercept_request'),
    path('proxy/history/', views.proxy_history, name='proxy_history'),
    path('proxy/add/', views.add_proxy_request, name='add_proxy_request'),
    path('proxy/clear/', views.clear_proxy_history, name='clear_proxy_history'),
    path('proxy/<int:req_id>/delete/', views.delete_proxy_request, name='delete_proxy_request'),
    path('proxy/<int:req_id>/forward/', views.forward_request, name='forward_request'),
    path('proxy/<int:req_id>/drop/', views.drop_request, name='drop_request'),
    path('proxy/<int:req_id>/modify/', views.modify_and_forward, name='modify_and_forward'),  # ← MANQUAIT

    # ── Intruder ──
    path('intruder/', views.intruder, name='intruder'),
    path('intruder/run/', views.run_intruder, name='run_intruder'),
    path('intruder/<int:intruder_id>/status/', views.intruder_status, name='intruder_status'),
    path('intruder/add-payload/', views.add_payload, name='add_payload'),

    # ── Repeater ──
    path('repeater/', views.repeater, name='repeater'),
    path('repeater/send/', views.send_repeater, name='send_repeater'),

    # ── Spider ──
    path('spider/', views.spider, name='spider'),
    path('spider/start/', views.start_spider, name='start_spider'),

    # ── Decoder ──
    path('decoder/', views.decoder, name='decoder'),
    path('decoder/encode/', views.decode_encode, name='decode_encode'),

    # ── Comparer ──
    path('comparer/', views.comparer, name='comparer'),
    path('comparer/compare/', views.compare_data, name='compare_data'),
]