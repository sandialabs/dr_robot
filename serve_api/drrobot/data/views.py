from django.shortcuts import render
from .models import Domains, Data
from django.http import JsonResponse 
# Create your views here.
def index(request):
    return JsonResponse({"res": "Hello, WOrld"})

def domain(request, domain_name):
    dname = domain_name.replace('.','_')

    data = Data.objects.filter(domain=dname)
    if data is None:
        return JsonResponse({})
    all_data = {}
    for res in data:
        if res.ip in all_data:
            all_data[res.ip] = {
                        "hostnames" : all_data[res.ip]["hostnames"] + [res.hostname],
                        "http_header" : res.http_headers,
                        "https_header" : res.https_headers,
                        "ip" : res.ip
                    }
        else:
            all_data[res.ip] = {
                        "hostnames" : [res.hostname],
                        "http_header" : res.http_headers,
                        "https_header" : res.https_headers,
                        "ip" : res.ip
                    }

    return JsonResponse(all_data)
