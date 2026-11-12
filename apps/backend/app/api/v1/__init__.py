"""All /api/v1 endpoints. Phase 1 exposes read-only views over the real database."""
from fastapi import APIRouter

from app.api.v1 import (
    briefings,
    captures,
    flows,
    hosts,
    investigations,
    protocols,
    settings,
    stats,
    timeline,
)

router = APIRouter(prefix="/api/v1")
for module in (stats, captures, hosts, flows, timeline, investigations, briefings, protocols, settings):
    router.include_router(module.router)
