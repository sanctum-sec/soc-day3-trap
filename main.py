import os
from fastapi import FastAPI, Depends, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import RequestValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from schemas.envelope import EventEnvelope

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Trap Ingest", docs_url="/docs")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

bearer = HTTPBearer(auto_error=False)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"detail": exc.errors()},
    )


@app.middleware("http")
async def validate_content_type(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/ingest":
        ct = request.headers.get("content-type", "")
        if "application/json" not in ct:
            return JSONResponse(
                status_code=400,
                content={"detail": "Content-Type must be application/json"},
            )
    return await call_next(request)


def verify_token(creds: HTTPAuthorizationCredentials | None = Security(bearer)):
    expected = os.environ.get("SOC_PROTOCOL_TOKEN", "")
    if not creds or not expected or creds.credentials != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/health")
def health():
    return {"status": "ok", "tool": "trap"}


@app.post("/ingest", status_code=202)
@limiter.limit("60/minute")
def ingest(request: Request, event: EventEnvelope, _: None = Depends(verify_token)):
    return {"status": "accepted", "event_id": event.event_id}
