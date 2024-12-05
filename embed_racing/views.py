import json
import logging
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required, permission_required
from django.utils.decorators import method_decorator
from django.views import View
from .models import TrackedRequest
from PIL import Image
from io import BytesIO
from itertools import groupby
from operator import itemgetter

logger = logging.getLogger(__name__)

@login_required
@permission_required('embed_racing.view_trackedrequest', raise_exception=True)
def generate_links(request):
    if request.method == 'POST':
        num_links = int(request.POST.get('num_links'))
        group_name = request.POST.get('group_name')
        
        generated_links = []
        base_url = request.build_absolute_uri('/')[:-1]  # Get the base URL
        
        for i in range(num_links):
            unique_id = f'link_{int(datetime.now().timestamp())}_{i}'
            tracked_request = TrackedRequest(
                unique_id=unique_id,
                group_name=group_name
            )
            tracked_request.save()
            generated_links.append(f"{base_url}/embed_racing/track/{unique_id}.gif")
        
        return JsonResponse({"generated_links": generated_links})
    
    return render(request, 'embed_racing/generate_links.html')


@login_required
@permission_required('embed_racing.view_trackedrequest', raise_exception=True)
def track_embed(request, unique_id):
    try:
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ip_address = request.META.get('REMOTE_ADDR', '')
        referrer = request.META.get('HTTP_REFERER', '')
        headers = json.dumps(dict(request.META))
        
        tracked_request = TrackedRequest.objects.filter(unique_id=unique_id).first()
        if not tracked_request:
            logger.error(f"No initial request found for unique_id {unique_id}")
            return HttpResponse("Invalid unique_id", status=404)

        tracked_request.ip_address = ip_address
        tracked_request.user_agent = user_agent
        tracked_request.referrer = referrer
        tracked_request.headers = headers
        tracked_request.timestamp = datetime.now()
        tracked_request.save()

        # Create the 1x1 GIF image
        image = Image.new('RGBA', (1, 1), (0, 0, 0, 0))
        img_io = BytesIO()
        image.save(img_io, 'GIF')
        img_io.seek(0)
        
        return HttpResponse(img_io, content_type='image/gif')
    except Exception as e:
        logger.error(f"Error processing request for {unique_id}: {str(e)}")
        return HttpResponse("Error processing the request", status=500)


# Local utility function, originally from Flask code, now moved into views
def detect_relays(logs):
    suspicious_ips = []
    
    # Loop over the list of dictionaries (logs)
    for log in logs:
        ip = log.get('ip_address', '')
        user_agent = log.get('user_agent', '')
        timestamp = log.get('timestamp')
        geolocation = log.get('geolocation')

        # Detect suspicious IPs based on geolocation or organization
        if is_google_hosted(ip) or is_suspicious_geo(geolocation) or is_suspicious_org(geolocation):
            suspicious_ips.append(ip)

    return suspicious_ips


# Mock utility functions for illustration, replace with your real logic
def is_google_hosted(ip):
    # Example: check if the IP is Google hosted, replace with your logic
    return "google" in ip

def is_suspicious_geo(geolocation):
    # Example: check if geolocation is suspicious, replace with your logic
    return geolocation is not None and geolocation.get('country') in ['SuspiciousCountry']

def is_suspicious_org(geolocation):
    # Example: check if organization is suspicious, replace with your logic
    return geolocation is not None and geolocation.get('organization') in ['SuspiciousOrg']


@method_decorator([login_required, permission_required('embed_racing.view_trackedrequest', raise_exception=True)], name='dispatch')
class DashboardView(View):

    def get(self, request):
        # Query TrackedRequest, similar to Flask query filter
        logs = TrackedRequest.objects.filter(hidden=False).order_by('unique_id')

        # Convert logs to a list of dictionaries, similar to the Flask version
        logs_list = [
            {
                "unique_id": log.unique_id,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "referrer": log.referrer,
                "geolocation": json.loads(log.geolocation) if log.geolocation else None,
                "timestamp": log.timestamp,
                "hidden": log.hidden
            }
            for log in logs
        ]

        # Group logs by unique_id using groupby
        logs_grouped = {
            key: list(group)
            for key, group in groupby(logs_list, key=itemgetter('unique_id'))
        }

        # Detect relays using the detect_relays function (now moved locally)
        suspicious_ips = detect_relays(logs_list)

        # Calculate total logs, unique IPs, and last updated timestamp
        total_logs = len(logs_list)
        unique_ips = len(set(log['ip_address'] for log in logs_list))
        last_updated = logs_list[-1]['timestamp'] if total_logs > 0 else 'N/A'

        # Render the dashboard, similar to Flask's render_template
        return render(
            request,
            'embed_racing/dashboard.html',
            {
                'logs': logs_grouped,
                'total_logs': total_logs,
                'unique_ips': unique_ips,
                'last_updated': last_updated,
                'suspicious_ips': suspicious_ips
            }
        )
