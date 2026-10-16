
import hmac
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from config import ObfuscationConfig
from obfuscator import Obfuscator

app = FastAPI(title="CheeseForge Obscura API")

API_TOKEN = os.environ.get("OBSCURA_API_TOKEN", "")
MAX_SIZE = 1024 * 1024


class ObfuscateRequest(BaseModel):
    code: str


@app.get("/")
def health():
    return {"status": "ok", "engine": "Obscura"}


@app.post("/obfuscate")
def obfuscate(
    body: ObfuscateRequest,
    x_api_token: str = Header(default="")
):
    if not API_TOKEN or not hmac.compare_digest(
        x_api_token, API_TOKEN
    ):
        raise HTTPException(status_code=401, detail="No autorizado")

    if not body.code.strip():
        raise HTTPException(status_code=400, detail="Código vacío")

    if len(body.code.encode("utf-8")) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="Máximo 1 MB")

    try:
        config = ObfuscationConfig(
            virtualize=True,
            vm_hardening="max"
        )
        result = Obfuscator(config).obfuscate(body.code)

        if not isinstance(result, str) or not result.strip():
            raise ValueError("Resultado vacío")

        return {"output": result}

    except Exception as exc:
        print(f"Obscura error: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=422,
            detail="No se pudo ofuscar el código. Puede contener sintaxis no compatible."
        ) from exc
