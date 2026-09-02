from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

app = FastAPI(
    title="Maven Security Vulnerability Scanner",
    description="Automated dependency and static vulnerability scanner for Maven projects (SIH J-001)",
    version="1.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api")


@app.get("/")
def root():
    return {
        "service": "Maven Application Security Vulnerability Scanner",
        "docs": "/docs",
        "health": "/api/health",
        "cli_usage": "python -m app.cli <path_or_zip>",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
