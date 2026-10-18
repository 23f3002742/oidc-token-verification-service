from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt, JWTError

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

PUBLIC_KEY = PUBLIC_KEY.replace("\\n", "\n").strip()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-5c3cs6b5.apps.exam.local"

app = FastAPI()

class VerifyRequest(BaseModel):
    token: str

@app.post("/verify")
def verify(req: VerifyRequest):
    try:
        claims = jwt.decode(
            req.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require_exp": True},
        )
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }
    except JWTError as e:
        print(f"JWT verification failed: {type(e).__name__}: {e}")
        return JSONResponse(status_code=401, content={"valid": False})