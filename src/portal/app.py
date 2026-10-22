"""
PHP2Shell Exposure Portal - web front end for the Foundry multi-agent system.
Calls Azure AI Foundry agents through the Responses API using the web app's managed identity,
and calls the PHP2Shell Checker API for instant (non-AI) scans.
"""
import os
import asyncio
import logging
from typing import List, Optional

import httpx
from azure.identity import DefaultAzureCredential
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

PROJECT_ENDPOINT = os.environ.get("PROJECT_ENDPOINT", "")
CHECKER_API = os.environ.get("CHECKER_API", "")
DEFAULT_SUB = os.environ.get("DEFAULT_SUBSCRIPTION_ID", "")
CHECKER_AUDIENCE = os.environ.get("CHECKER_AUDIENCE", "")
AGENT_PREFIX = os.environ.get("AGENT_PREFIX", "php2shell")
AGENTS = {"orchestrator": f"{AGENT_PREFIX}-orchestrator", "scanner": f"{AGENT_PREFIX}-url-scanner",
          "inventory": f"{AGENT_PREFIX}-azure-inventory", "advisor": f"{AGENT_PREFIX}-remediation-advisor"}
ALLOWED_SUBS = {s.strip().lower() for s in os.environ.get("ALLOWED_SUBSCRIPTION_IDS", "").split(",") if s.strip()}
MAX_MESSAGE_CHARS = 8000

log = logging.getLogger("php2shell.portal")
logging.basicConfig(level=logging.INFO)

_cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
app = FastAPI(title="PHP2Shell Exposure Portal")
STATIC = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


async def _token(scope: str = "https://ai.azure.com/.default") -> str:
    t = await asyncio.to_thread(_cred.get_token, scope)
    return t.token


async def _checker_headers() -> dict:
    if not CHECKER_AUDIENCE:
        return {}
    return {"Authorization": "Bearer " + await _token(f"{CHECKER_AUDIENCE}/.default")}


async def call_agent(agent_key: str, text: str, previous_response_id: Optional[str] = None) -> dict:
    name = AGENTS.get(agent_key, agent_key)
    body = {"input": text, "agent_reference": {"name": name, "type": "agent_reference"}}
    if previous_response_id:
        body["previous_response_id"] = previous_response_id
    headers = {"Authorization": f"Bearer {await _token()}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=240) as c:
        r = await c.post(f"{PROJECT_ENDPOINT}/openai/v1/responses", json=body, headers=headers)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, r.text[:800])
    data = r.json()
    text_out, tools = [], []
    for item in data.get("output", []):
        t = item.get("type")
        if t == "message":
            for part in item.get("content", []):
                if part.get("type") in ("output_text", "text"):
                    text_out.append(part.get("text", ""))
        elif t and t.endswith("_call"):
            op = item.get("name") or item.get("operation_id") or (item.get("openapi") or {}).get("operation_id") or t
            tools.append(op)
    return {"agent": name, "response_id": data.get("id"), "text": "\n".join(text_out).strip(),
            "tool_calls": tools, "usage": data.get("usage", {})}


def signed_in_user(request: Request) -> str:
    """App Service Authentication is mandatory; it injects (and strips client-supplied) X-MS-CLIENT-PRINCIPAL headers.
    Refuse to act if they are missing, e.g. when the app runs without Easy Auth."""
    user = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME") or request.headers.get("X-MS-CLIENT-PRINCIPAL-ID")
    if not user:
        raise HTTPException(401, "Sign-in required")
    return user


class AgentRequest(BaseModel):
    agent: str = "orchestrator"
    message: str = Field(..., max_length=MAX_MESSAGE_CHARS)
    previous_response_id: Optional[str] = None


class ScanRequest(BaseModel):
    urls: List[str] = Field([], max_length=50)
    subscription_ids: List[str] = Field([], max_length=20)
    authorised: bool = False


@app.post("/api/agent")
async def api_agent(req: AgentRequest, user: str = Depends(signed_in_user)):
    if req.agent not in AGENTS:
        raise HTTPException(400, "unknown agent")
    log.info("agent call by %s to %s (%d chars)", user, req.agent, len(req.message))
    return await call_agent(req.agent, req.message, req.previous_response_id)


@app.post("/api/scan")
async def api_scan(req: ScanRequest, user: str = Depends(signed_in_user)):
    if not req.authorised:
        raise HTTPException(400, "Confirm that your organisation owns or is authorised to assess these systems")
    subs = [s.strip().lower() for s in req.subscription_ids if s.strip()]
    if any(s not in ALLOWED_SUBS for s in subs):
        raise HTTPException(403, "Subscription not enabled for this deployment")
    log.info("scan by %s (attested authorised): urls=%s subscriptions=%s", user, req.urls, subs)
    out = {"urls": [], "azure": None}
    headers = await _checker_headers()
    async with httpx.AsyncClient(timeout=180, headers=headers) as c:
        if req.urls:
            r = await c.post(f"{CHECKER_API}/check/batch", json={"urls": req.urls})
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text[:300])
            out["urls"] = r.json()
        if subs:
            r = await c.post(f"{CHECKER_API}/inventory/azure", json={"subscription_ids": subs, "probe": True})
            out["azure"] = r.json() if r.status_code < 400 else {"error": r.text[:300]}
    return out


@app.get("/api/config")
async def api_config(user: str = Depends(signed_in_user)):
    return {"default_subscription": DEFAULT_SUB, "checker_api": CHECKER_API, "agents": AGENTS,
            "project": PROJECT_ENDPOINT.split("/api/projects/")[-1], "user": user}


@app.get("/healthz")
async def health():
    return {"ok": True}


@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))
