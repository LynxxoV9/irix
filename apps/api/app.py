from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apps.api.config import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure evidence storage directory exists at startup
    settings.storage_path
    yield
    # Cleanup tasks on shutdown if needed


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"{settings.PROJECT_BASELINE} - Autonomous DFIR Investigation Platform",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Enable CORS for web UI development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["General"])
def root():
    return {
        "project": settings.PROJECT_NAME,
        "baseline": settings.PROJECT_BASELINE,
        "version": settings.VERSION,
        "status": "online",
        "docs_url": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "storage_ready": settings.storage_path.exists(),
        "database_configured": bool(settings.DATABASE_URL),
    }


@app.get("/api/v1/info", tags=["Metadata"])
def get_platform_info():
    return {
        "project": settings.PROJECT_NAME,
        "baseline": settings.PROJECT_BASELINE,
        "hackathon": "Nebius × NVIDIA Global AI Hackathon 2026",
        "track": "Best Apps and Agents",
        "version": settings.VERSION,
        "supported_forensic_domains": [
            "Memory (Volatility 3)",
            "Disk & Filesystem (TSK)",
            "Windows Logs (EVTX)",
            "Prefetch (PECmd)",
            "Signatures (YARA)",
            "Network (TShark)",
            "Threat Intel (Tavily)",
        ],
    }
