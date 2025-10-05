import os
import uuid
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

# In-memory session store
sessions = {}

# -------------------------------
# Allowed origins (frontend)
# -------------------------------
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://test-cookie-fn.vercel.app")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# Simulated OAuth redirect
# -------------------------------

@app.get("/auth/start")
def auth_start():
    print("Redirecting to fake OAuth provider...")
    # Simulate provider returning a code
    # Redirects back to /auth/callback on same backend
    return RedirectResponse(url=f"{os.getenv('BACKEND_URL', 'https://test-cookie-a0bv.onrender.com')}/auth/callback?code=fake_oauth_code")

# -------------------------------
# Simulated OAuth callback
# -------------------------------

@app.get("/auth/callback")
def auth_callback(code: str):
    print(f"Received fake auth code: {code}")

    access_token = f"access-{uuid.uuid4()}"
    refresh_token = f"refresh-{uuid.uuid4()}"

    sessions[access_token] = {
        "user": {"username": "raghav"},
        "expires_at": datetime.utcnow() + timedelta(seconds=20),
        "refresh_token": refresh_token,
        "refresh_expires_at": datetime.utcnow() + timedelta(minutes=5)
    }

    # Redirect user to frontend dashboard
    response = RedirectResponse(url=f"{FRONTEND_URL}/dashboard.html")

    # ✅ Cookies: must be Secure + SameSite=None for cross-site HTTPS
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="none",
        secure=True,
        max_age=1200,
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="none",
        secure=True,
        max_age=300,
        path="/"
    )

    return response

# -------------------------------
# Protected route (/me)
# -------------------------------

@app.get("/me")
def get_user(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token or access_token not in sessions:
        raise HTTPException(status_code=401, detail="Unauthorized")

    session = sessions[access_token]
    if datetime.utcnow() > session["expires_at"]:
        raise HTTPException(status_code=401, detail="Access token expired")

    return {"user": session["user"], "access_expires_at": session["expires_at"].isoformat()}

# -------------------------------
# Refresh endpoint (/refresh)
# -------------------------------

@app.post("/refresh")
def refresh_tokens(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    session = next((s for s in sessions.values() if s["refresh_token"] == refresh_token), None)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if datetime.utcnow() > session["refresh_expires_at"]:
        raise HTTPException(status_code=401, detail="Refresh token expired")

    new_access = f"access-{uuid.uuid4()}"
    sessions[new_access] = {
        "user": session["user"],
        "expires_at": datetime.utcnow() + timedelta(seconds=20),
        "refresh_token": refresh_token,
        "refresh_expires_at": session["refresh_expires_at"]
    }

    response = JSONResponse({"message": "Access token refreshed"})
    response.set_cookie(
        key="access_token",
        value=new_access,
        httponly=True,
        samesite="none",
        secure=True,
        max_age=1200
    )
    return response

# -------------------------------
# Logout endpoint
# -------------------------------

@app.get("/logout")
def logout():
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie("access_token", samesite="none", secure=True)
    response.delete_cookie("refresh_token", samesite="none", secure=True)
    return response

