import os
import uuid
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()

# In-memory store for sessions
sessions = {}

# Allow cross-origin from frontend
allowed_origin = []
if os.getenv("FRONTEND_URL"):
    allowed_origin.append(os.getenv("FRONTEND_URL"))
allowed_origin.append("http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origin,
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
    return RedirectResponse("http://localhost:8000/auth/callback?code=fake_oauth_code")


# -------------------------------
# Simulated OAuth callback
# -------------------------------

@app.get("/auth/callback")
def auth_callback(code: str):
    print(f"Received fake auth code: {code}")

    # Create fake tokens
    access_token = f"access-{uuid.uuid4()}"
    refresh_token = f"refresh-{uuid.uuid4()}"

    # Store both in our in-memory DB
    sessions[access_token] = {
        "user": {"username": "raghav"},
        "expires_at": datetime.utcnow() + timedelta(seconds=20),  # short life
        "refresh_token": refresh_token,
        "refresh_expires_at": datetime.utcnow() + timedelta(minutes=5)
    }

    # Create redirect response and set cookies
    response = RedirectResponse(url="http://localhost:3000/dashboard.html")
    
    # For localhost, use sameSite="lax" with secure=False
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",  # Changed from "None"
        secure=False,
        max_age=1200  # 20 minutes in seconds
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",  # Changed from "None"
        secure=False,
        max_age=300  # 5 minutes in seconds
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

    # Find session with this refresh token
    session = next((s for s in sessions.values() if s["refresh_token"] == refresh_token), None)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if datetime.utcnow() > session["refresh_expires_at"]:
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # Create a new access token
    new_access = f"access-{uuid.uuid4()}"
    sessions[new_access] = {
        "user": session["user"],
        "expires_at": datetime.utcnow() + timedelta(seconds=20),
        "refresh_token": refresh_token,
        "refresh_expires_at": session["refresh_expires_at"]
    }

    # Create response and set new access cookie
    response = JSONResponse({"message": "Access token refreshed"})
    response.set_cookie(
        key="access_token",
        value=new_access,
        httponly=True,
        samesite="lax",  # Changed from "None"
        secure=False,
        max_age=1200  # 20 minutes
    )
    return response


# -------------------------------
# Logout endpoint
# -------------------------------

@app.get("/logout")
def logout():
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie("access_token", samesite="lax")
    response.delete_cookie("refresh_token", samesite="lax")
    return response