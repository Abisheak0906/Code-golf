from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
from jose import jwt
from RestrictedPython import compile_restricted, safe_globals
from RestrictedPython.Guards import guarded_iter_unpack_sequence, safe_builtins
import sys
from io import StringIO
import re
import httpx

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"

ALLOWED_EMAIL_DOMAINS = ["@ds.study.iitm.ac.in", "@es.study.iitm.ac.in"]

class User(BaseModel):
    user_id: str
    email: str
    name: str
    role: str
    picture: Optional[str] = None
    created_at: datetime

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str = "participant"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Challenge(BaseModel):
    challenge_id: str
    title: str
    description: str
    time_limit: int
    created_by: str
    created_at: datetime
    is_active: bool = True

class ChallengeCreate(BaseModel):
    title: str
    description: str
    time_limit: int

class TestCase(BaseModel):
    test_case_id: str
    challenge_id: str
    input_data: str
    expected_output: str
    is_hidden: bool = True

class TestCaseCreate(BaseModel):
    input_data: str
    expected_output: str
    is_hidden: bool = True

class Submission(BaseModel):
    submission_id: str
    challenge_id: str
    user_id: str
    code: str
    character_count: int
    submitted_at: datetime
    status: str
    execution_result: Optional[str] = None

class SubmissionCreate(BaseModel):
    code: str

class LeaderboardEntry(BaseModel):
    user_id: str
    user_name: str
    best_character_count: int
    best_submission_time: datetime
    rank: int

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request) -> dict:
    token = None
    
    if "session_token" in request.cookies:
        token = request.cookies.get("session_token")
    elif "Authorization" in request.headers:
        auth_header = request.headers.get("Authorization")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    expires_at = session["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")
    
    user = await db.users.find_one({"user_id": session["user_id"]}, {"_id": 0})
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

def validate_email_domain(email: str) -> bool:
    return any(email.endswith(domain) for domain in ALLOWED_EMAIL_DOMAINS)

def execute_python_code(code: str, input_data: str) -> tuple[bool, str]:
    try:
        restricted_globals = {
            '__builtins__': safe_builtins,
            '_getiter_': guarded_iter_unpack_sequence,
            '_iter_unpack_sequence_': guarded_iter_unpack_sequence,
        }
        
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        sys.stdin = StringIO(input_data)
        sys.stdout = StringIO()
        
        byte_code = compile_restricted(code, '<string>', 'exec')
        exec(byte_code, restricted_globals)
        
        output = sys.stdout.getvalue()
        
        sys.stdin = old_stdin
        sys.stdout = old_stdout
        
        return True, output.strip()
    except Exception as e:
        sys.stdin = old_stdin
        sys.stdout = old_stdout
        return False, str(e)

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    if not validate_email_domain(user_data.email):
        raise HTTPException(
            status_code=400,
            detail=f"Only IITM emails are allowed ({', '.join(ALLOWED_EMAIL_DOMAINS)})"
        )
    
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    hashed_password = hash_password(user_data.password)
    
    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
        "name": user_data.name,
        "role": user_data.role,
        "password": hashed_password,
        "picture": None,
        "created_at": datetime.now(timezone.utc)
    }
    
    await db.users.insert_one(user_doc)
    
    token = create_access_token({"user_id": user_id})
    
    session_doc = {
        "user_id": user_id,
        "session_token": token,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "created_at": datetime.now(timezone.utc)
    }
    await db.user_sessions.insert_one(session_doc)
    
    user = await db.users.find_one({"user_id": user_id}, {"_id": 0, "password": 0})
    
    return {"token": token, "user": user}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"user_id": user["user_id"]})
    
    session_doc = {
        "user_id": user["user_id"],
        "session_token": token,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "created_at": datetime.now(timezone.utc)
    }
    await db.user_sessions.insert_one(session_doc)
    
    user_data = await db.users.find_one({"user_id": user["user_id"]}, {"_id": 0, "password": 0})
    
    return {"token": token, "user": user_data}

@api_router.get("/auth/google")
async def google_auth_redirect(redirect_url: str):
    auth_url = f"https://auth.emergentagent.com/?redirect={redirect_url}"
    return {"auth_url": auth_url}

@api_router.get("/auth/session")
async def exchange_session(request: Request, response: Response):
    session_id = request.headers.get("X-Session-ID")
    
    if not session_id:
        raise HTTPException(status_code=400, detail="Session ID required")
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": session_id}
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid session")
        
        session_data = resp.json()
    
    if not validate_email_domain(session_data["email"]):
        raise HTTPException(
            status_code=403,
            detail=f"Only IITM emails are allowed ({', '.join(ALLOWED_EMAIL_DOMAINS)})"
        )
    
    user = await db.users.find_one({"email": session_data["email"]})
    
    if user:
        user_id = user["user_id"]
        await db.users.update_one(
            {"user_id": user_id},
            {"$set": {
                "name": session_data.get("name", user.get("name", "")),
                "picture": session_data.get("picture", user.get("picture"))
            }}
        )
    else:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user_doc = {
            "user_id": user_id,
            "email": session_data["email"],
            "name": session_data.get("name", ""),
            "role": "participant",
            "picture": session_data.get("picture"),
            "created_at": datetime.now(timezone.utc)
        }
        await db.users.insert_one(user_doc)
    
    session_token = session_data["session_token"]
    
    session_doc = {
        "user_id": user_id,
        "session_token": session_token,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "created_at": datetime.now(timezone.utc)
    }
    await db.user_sessions.insert_one(session_doc)
    
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=7*24*60*60
    )
    
    user_data = await db.users.find_one({"user_id": user_id}, {"_id": 0, "password": 0})
    
    return {"user": user_data, "token": session_token}

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    return user

@api_router.post("/auth/logout")
async def logout(response: Response, user: dict = Depends(get_current_user)):
    await db.user_sessions.delete_many({"user_id": user["user_id"]})
    response.delete_cookie("session_token", path="/")
    return {"message": "Logged out successfully"}

@api_router.get("/challenges")
async def get_challenges(user: dict = Depends(get_current_user)):
    challenges = await db.challenges.find({"is_active": True}, {"_id": 0}).to_list(1000)
    
    for challenge in challenges:
        if isinstance(challenge.get('created_at'), str):
            challenge['created_at'] = datetime.fromisoformat(challenge['created_at'])
    
    return challenges

@api_router.post("/challenges")
async def create_challenge(challenge_data: ChallengeCreate, user: dict = Depends(get_current_user)):
    if user["role"] != "coordinator":
        raise HTTPException(status_code=403, detail="Only coordinators can create challenges")
    
    challenge_id = f"challenge_{uuid.uuid4().hex[:12]}"
    
    challenge_doc = {
        "challenge_id": challenge_id,
        "title": challenge_data.title,
        "description": challenge_data.description,
        "time_limit": challenge_data.time_limit,
        "created_by": user["user_id"],
        "created_at": datetime.now(timezone.utc),
        "is_active": True
    }
    
    await db.challenges.insert_one(challenge_doc)
    
    challenge = await db.challenges.find_one({"challenge_id": challenge_id}, {"_id": 0})
    return challenge

@api_router.get("/challenges/{challenge_id}")
async def get_challenge(challenge_id: str, user: dict = Depends(get_current_user)):
    challenge = await db.challenges.find_one({"challenge_id": challenge_id}, {"_id": 0})
    
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    if isinstance(challenge.get('created_at'), str):
        challenge['created_at'] = datetime.fromisoformat(challenge['created_at'])
    
    if user["role"] == "coordinator":
        test_cases = await db.test_cases.find({"challenge_id": challenge_id}, {"_id": 0}).to_list(1000)
        challenge["test_cases"] = test_cases
    else:
        visible_test_cases = await db.test_cases.find(
            {"challenge_id": challenge_id, "is_hidden": False},
            {"_id": 0}
        ).to_list(1000)
        challenge["sample_test_cases"] = visible_test_cases
    
    return challenge

@api_router.put("/challenges/{challenge_id}")
async def update_challenge(challenge_id: str, challenge_data: ChallengeCreate, user: dict = Depends(get_current_user)):
    if user["role"] != "coordinator":
        raise HTTPException(status_code=403, detail="Only coordinators can update challenges")
    
    result = await db.challenges.update_one(
        {"challenge_id": challenge_id},
        {"$set": challenge_data.model_dump()}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    challenge = await db.challenges.find_one({"challenge_id": challenge_id}, {"_id": 0})
    return challenge

@api_router.delete("/challenges/{challenge_id}")
async def delete_challenge(challenge_id: str, user: dict = Depends(get_current_user)):
    if user["role"] != "coordinator":
        raise HTTPException(status_code=403, detail="Only coordinators can delete challenges")
    
    result = await db.challenges.update_one(
        {"challenge_id": challenge_id},
        {"$set": {"is_active": False}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return {"message": "Challenge deleted successfully"}

@api_router.post("/challenges/{challenge_id}/test-cases")
async def add_test_case(challenge_id: str, test_case_data: TestCaseCreate, user: dict = Depends(get_current_user)):
    if user["role"] != "coordinator":
        raise HTTPException(status_code=403, detail="Only coordinators can add test cases")
    
    challenge = await db.challenges.find_one({"challenge_id": challenge_id})
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    test_case_id = f"testcase_{uuid.uuid4().hex[:12]}"
    
    test_case_doc = {
        "test_case_id": test_case_id,
        "challenge_id": challenge_id,
        "input_data": test_case_data.input_data,
        "expected_output": test_case_data.expected_output,
        "is_hidden": test_case_data.is_hidden
    }
    
    await db.test_cases.insert_one(test_case_doc)
    
    test_case = await db.test_cases.find_one({"test_case_id": test_case_id}, {"_id": 0})
    return test_case

@api_router.post("/challenges/{challenge_id}/submit")
async def submit_code(challenge_id: str, submission_data: SubmissionCreate, user: dict = Depends(get_current_user)):
    challenge = await db.challenges.find_one({"challenge_id": challenge_id})
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    test_cases = await db.test_cases.find({"challenge_id": challenge_id}, {"_id": 0}).to_list(1000)
    
    if not test_cases:
        raise HTTPException(status_code=400, detail="No test cases available for this challenge")
    
    all_passed = True
    execution_logs = []
    
    for test_case in test_cases:
        success, output = execute_python_code(submission_data.code, test_case["input_data"])
        
        if not success:
            all_passed = False
            execution_logs.append({
                "test_case_id": test_case["test_case_id"],
                "status": "error",
                "error": output
            })
            break
        
        if output != test_case["expected_output"].strip():
            all_passed = False
            execution_logs.append({
                "test_case_id": test_case["test_case_id"],
                "status": "failed",
                "expected": test_case["expected_output"],
                "got": output
            })
        else:
            execution_logs.append({
                "test_case_id": test_case["test_case_id"],
                "status": "passed"
            })
    
    submission_id = f"submission_{uuid.uuid4().hex[:12]}"
    character_count = len(submission_data.code)
    
    submission_doc = {
        "submission_id": submission_id,
        "challenge_id": challenge_id,
        "user_id": user["user_id"],
        "code": submission_data.code,
        "character_count": character_count,
        "submitted_at": datetime.now(timezone.utc),
        "status": "passed" if all_passed else "failed",
        "execution_result": execution_logs
    }
    
    await db.submissions.insert_one(submission_doc)
    
    if all_passed:
        existing_leaderboard = await db.leaderboard.find_one({
            "challenge_id": challenge_id,
            "user_id": user["user_id"]
        })
        
        if not existing_leaderboard or character_count < existing_leaderboard["best_character_count"]:
            await db.leaderboard.update_one(
                {"challenge_id": challenge_id, "user_id": user["user_id"]},
                {"$set": {
                    "challenge_id": challenge_id,
                    "user_id": user["user_id"],
                    "user_name": user["name"],
                    "best_character_count": character_count,
                    "best_submission_time": datetime.now(timezone.utc)
                }},
                upsert=True
            )
    
    submission = await db.submissions.find_one({"submission_id": submission_id}, {"_id": 0})
    return submission

@api_router.get("/challenges/{challenge_id}/leaderboard")
async def get_leaderboard(challenge_id: str, user: dict = Depends(get_current_user)):
    leaderboard = await db.leaderboard.find(
        {"challenge_id": challenge_id},
        {"_id": 0}
    ).sort([
        ("best_character_count", 1),
        ("best_submission_time", 1)
    ]).to_list(1000)
    
    for idx, entry in enumerate(leaderboard, 1):
        entry["rank"] = idx
        if isinstance(entry.get('best_submission_time'), str):
            entry['best_submission_time'] = datetime.fromisoformat(entry['best_submission_time'])
    
    return leaderboard

@api_router.get("/submissions/history")
async def get_submission_history(user: dict = Depends(get_current_user)):
    submissions = await db.submissions.find(
        {"user_id": user["user_id"]},
        {"_id": 0}
    ).sort("submitted_at", -1).to_list(1000)
    
    for submission in submissions:
        if isinstance(submission.get('submitted_at'), str):
            submission['submitted_at'] = datetime.fromisoformat(submission['submitted_at'])
    
    return submissions

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
