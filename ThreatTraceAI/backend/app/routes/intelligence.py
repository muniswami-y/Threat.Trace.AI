from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from app.services.threat_intelligence import check_urls, check_domains
from app.services.geolocation import geolocate_ips

router = APIRouter(prefix="/api/intelligence", tags=["Intelligence"])

class UrlCheckRequest(BaseModel):
    urls: List[str]

class DomainCheckRequest(BaseModel):
    domains: List[str]

class IpCheckRequest(BaseModel):
    ips: List[str]

@router.post("/urls")
async def check_url_reputation(payload: UrlCheckRequest):
    return await check_urls(payload.urls)

@router.post("/domains")
async def check_domain_reputation(payload: DomainCheckRequest):
    return await check_domains(payload.domains)

@router.post("/geo")
async def geo_lookup(payload: IpCheckRequest):
    return await geolocate_ips(payload.ips)
