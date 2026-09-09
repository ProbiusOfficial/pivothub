from fastapi import APIRouter

from . import attack, creds, export, flags, hosts, links, projects, recon, shells, stage, \
    timeline, tools

api_router = APIRouter(prefix="/api")
api_router.include_router(projects.router)
api_router.include_router(attack.router)
api_router.include_router(tools.router)
api_router.include_router(hosts.router)
api_router.include_router(shells.router)
api_router.include_router(recon.router)
api_router.include_router(links.router)
api_router.include_router(creds.router)
api_router.include_router(flags.router)
api_router.include_router(timeline.router)
api_router.include_router(export.router)
api_router.include_router(stage.router)
