
import logging
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from backend.app.main import analyze_scam_message



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("shadowtrace")



app = FastAPI(
    title="SHADOWTRACE API",
    description="AI-powered scam intelligence backend",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)



@app.middleware("http")
async def log_requests(request, call_next):
    start_time = time.perf_counter()

    logger.info(
        "Request started: %s %s",
        request.method,
        request.url.path
    )

    try:
        response = await call_next(request)

        duration = time.perf_counter() - start_time

        logger.info(
            "Request completed: %s %s | Status: %s | Duration: %.4f seconds",
            request.method,
            request.url.path,
            response.status_code,
            duration
        )

        return response

    except Exception:
        logger.exception(
            "Request failed: %s %s",
            request.method,
            request.url.path
        )
        raise



class AnalyzeRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=5000
    )

    @field_validator("message")
    @classmethod
    def validate_message(cls, value):
        if not value.strip():
            raise ValueError(
                "Message cannot contain only whitespace."
            )

        return value



@app.get("/")
def root():
    return {
        "status": "online",
        "project": "SHADOWTRACE"
    }



@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    try:
        return analyze_scam_message(request.message)

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error)
        )
def test_cors_allows_localhost_frontend():
    response = client.options(
        "/analyze",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == (
        "http://localhost:3000"
    )