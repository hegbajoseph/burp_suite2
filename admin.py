from django.contrib import admin
from .models import (
    ScanTarget, ScanResult, ProxyRequest,
    IntruderPayload, RepeaterRequest, SpiderResult, DecoderData
)


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ['id', 'url', 'name', 'status', 'created_at']
    list_filter = ['status']
    search_fields = ['url', 'name']


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'issue_type', 'severity', 'url', 'discovered_at']
    list_filter = ['severity']
    search_fields = ['issue_type', 'url']


@admin.register(ProxyRequest)
class ProxyRequestAdmin(admin.ModelAdmin):
    list_display = ['id', 'method', 'url', 'response_status', 'response_time', 'timestamp']
    list_filter = ['method', 'intercepted']
    search_fields = ['url']


@admin.register(IntruderPayload)
class IntruderPayloadAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'attack_type', 'target_url', 'status', 'created_at']
    list_filter = ['attack_type', 'status']


@admin.register(RepeaterRequest)
class RepeaterRequestAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'method', 'url', 'response_status', 'updated_at']
    search_fields = ['url', 'name']


@admin.register(SpiderResult)
class SpiderResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'url', 'status_code', 'content_type', 'discovered_at']
    list_filter = ['status_code']
    search_fields = ['url']


@admin.register(DecoderData)
class DecoderDataAdmin(admin.ModelAdmin):
    list_display = ['id', 'encoding_type', 'operation', 'created_at']
    list_filter = ['encoding_type', 'operation']