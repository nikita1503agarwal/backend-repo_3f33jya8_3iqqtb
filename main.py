import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Court, Review, Post, Comment, Event

# -----------------------------
# Auth setup
# -----------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 14  # 14 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[str] = None


# Helper to convert ObjectId

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Auth endpoints
# -----------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.user.find_one({"_id": oid(user_id)})
    if not user:
        raise credentials_exception
    user["_id"] = str(user["_id"])  # serialize
    return user


@app.post("/auth/signup", response_model=Token)
def signup(email: str = Form(...), password: str = Form(...), display_name: str = Form(...)):
    existing = db.user.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use")

    user = User(
        email=email,
        password_hash=get_password_hash(password),
        display_name=display_name,
        role="user",
    )
    user_id = create_document("user", user)

    token = create_access_token({"sub": user_id})
    return Token(access_token=token)


@app.post("/auth/token", response_model=Token)
def login(email: str = Form(...), password: str = Form(...)):
    user = db.user.find_one({"email": email})
    if not user or not verify_password(password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


# -----------------------------
# Profile endpoints
# -----------------------------
@app.get("/me")
def me(current=Depends(get_current_user)):
    return current


@app.put("/me")
def update_me(payload: dict, current=Depends(get_current_user)):
    # Allow updating profile fields but not email/password directly here
    updatable_fields = {
        "display_name",
        "avatar_url",
        "home_city",
        "home_court_id",
        "dupr_score",
        "dupr_profile_url",
        "skill_level",
        "play_style",
        "bio",
    }
    update_doc = {k: v for k, v in payload.items() if k in updatable_fields}
    if not update_doc:
        return current
    update_doc["updated_at"] = datetime.now(timezone.utc)
    db.user.update_one({"_id": oid(current["_id"])}, {"$set": update_doc})
    updated = db.user.find_one({"_id": oid(current["_id"])})
    updated["_id"] = str(updated["_id"])
    return updated


# -----------------------------
# Courts
# -----------------------------
@app.post("/courts")
def create_court(court: Court, current=Depends(get_current_user)):
    # Non-admins create pending courts
    if current.get("role") != "admin":
        court.status = "pending review"
    court.added_by_user_id = current["_id"]
    cid = create_document("court", court)
    return {"id": cid}


@app.get("/courts")
def list_courts(status: Optional[str] = "active", q: Optional[str] = None, indoor_outdoor: Optional[str] = None,
                min_courts: Optional[int] = None, court_type: Optional[str] = None, lighting: Optional[str] = None):
    filter_dict = {}
    if status:
        filter_dict["status"] = status
    if q:
        filter_dict["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"address_city": {"$regex": q, "$options": "i"}},
        ]
    if indoor_outdoor:
        filter_dict["indoor_outdoor"] = indoor_outdoor
    if min_courts is not None:
        filter_dict["number_of_courts"] = {"$gte": min_courts}
    if court_type:
        filter_dict["court_type"] = court_type
    if lighting:
        filter_dict["lighting"] = lighting

    items = get_documents("court", filter_dict)
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.get("/courts/{court_id}")
def get_court(court_id: str):
    c = db.court.find_one({"_id": oid(court_id)})
    if not c:
        raise HTTPException(status_code=404, detail="Court not found")
    c["_id"] = str(c["_id"]) 
    # attach average rating
    ratings = list(db.review.find({"court_id": court_id}))
    if ratings:
        avg = sum(r.get("rating", 0) for r in ratings) / len(ratings)
        c["average_rating"] = round(avg, 2)
        c["reviews_count"] = len(ratings)
    else:
        c["average_rating"] = None
        c["reviews_count"] = 0
    # upcoming events
    now_iso = datetime.now(timezone.utc).date().isoformat()
    events = list(db.event.find({"court_id": court_id, "date": {"$gte": now_iso}}).sort("date", 1))
    for e in events:
        e["_id"] = str(e["_id"]) 
    c["upcoming_events"] = events
    # frequent players (favorited)
    users = list(db.user.find({"favorites": court_id}, {"display_name": 1, "dupr_score": 1, "skill_level": 1}))
    for u in users:
        u["_id"] = str(u["_id"]) 
    c["frequent_players"] = users
    return c


# Photos upload: accept URLs for simplicity
@app.post("/courts/{court_id}/photos")
def add_court_photo(court_id: str, photo_url: str = Form(...), current=Depends(get_current_user)):
    court = db.court.find_one({"_id": oid(court_id)})
    if not court:
        raise HTTPException(status_code=404, detail="Court not found")
    db.court.update_one({"_id": oid(court_id)}, {"$push": {"photos": photo_url}})
    return {"ok": True}


# Reviews
@app.post("/courts/{court_id}/reviews")
def add_review(court_id: str, review: Review, current=Depends(get_current_user)):
    if review.court_id != court_id:
        raise HTTPException(status_code=400, detail="Mismatched court id")
    review.user_id = current["_id"]
    rid = create_document("review", review)
    return {"id": rid}


@app.get("/courts/{court_id}/reviews")
def list_reviews(court_id: str):
    rs = list(db.review.find({"court_id": court_id}).sort("created_at", -1))
    for r in rs:
        r["_id"] = str(r["_id"]) 
    return rs


# Favorites
@app.post("/courts/{court_id}/favorite")
def favorite_court(court_id: str, current=Depends(get_current_user)):
    db.user.update_one({"_id": oid(current["_id"])}, {"$addToSet": {"favorites": court_id}})
    return {"ok": True}


@app.delete("/courts/{court_id}/favorite")
def unfavorite_court(court_id: str, current=Depends(get_current_user)):
    db.user.update_one({"_id": oid(current["_id"])}, {"$pull": {"favorites": court_id}})
    return {"ok": True}


# -----------------------------
# Community feed
# -----------------------------
@app.get("/feed")
def get_feed(filter: Optional[str] = "all", current=Depends(get_current_user)):
    query = {}
    if filter == "mycourts":
        favs = current.get("favorites", [])
        if favs:
            query["court_id"] = {"$in": favs}
        else:
            return []
    elif filter == "nearme":
        # Placeholder: without geo index, just return recent
        pass
    posts = list(db.post.find(query).sort("created_at", -1).limit(100))
    for p in posts:
        p["_id"] = str(p["_id"]) 
    return posts


@app.post("/feed")
def create_post(post: Post, current=Depends(get_current_user)):
    post.author_id = current["_id"]
    pid = create_document("post", post)
    return {"id": pid}


@app.post("/feed/{post_id}/like")
def like_post(post_id: str, current=Depends(get_current_user)):
    db.post.update_one({"_id": oid(post_id)}, {"$addToSet": {"likes": current["_id"]}})
    return {"ok": True}


@app.post("/feed/{post_id}/comment")
def comment_post(post_id: str, payload: Comment, current=Depends(get_current_user)):
    if payload.post_id != post_id:
        raise HTTPException(status_code=400, detail="Mismatched post id")
    payload.author_id = current["_id"]
    cid = create_document("comment", payload)
    return {"id": cid}


@app.get("/feed/{post_id}/comments")
def list_comments(post_id: str):
    cs = list(db.comment.find({"post_id": post_id}).sort("created_at", 1))
    for c in cs:
        c["_id"] = str(c["_id"]) 
    return cs


# -----------------------------
# Events
# -----------------------------
@app.post("/events")
def create_event(event: Event, current=Depends(get_current_user)):
    event.organizer_id = current["_id"]
    event.attendees = [current["_id"]]
    eid = create_document("event", event)
    return {"id": eid}


@app.get("/events")
def list_events(court_id: Optional[str] = None):
    f = {}
    if court_id:
        f["court_id"] = court_id
    es = list(db.event.find(f).sort([("date", 1), ("start_time", 1)]))
    for e in es:
        e["_id"] = str(e["_id"]) 
    return es


@app.post("/events/{event_id}/join")
def join_event(event_id: str, current=Depends(get_current_user)):
    ev = db.event.find_one({"_id": oid(event_id)})
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    if ev.get("max_players") and len(ev.get("attendees", [])) >= ev["max_players"]:
        raise HTTPException(status_code=400, detail="Event is full")
    db.event.update_one({"_id": oid(event_id)}, {"$addToSet": {"attendees": current["_id"]}})
    return {"ok": True}


@app.post("/events/{event_id}/leave")
def leave_event(event_id: str, current=Depends(get_current_user)):
    db.event.update_one({"_id": oid(event_id)}, {"$pull": {"attendees": current["_id"]}})
    return {"ok": True}


# -----------------------------
# Admin endpoints
# -----------------------------
@app.post("/admin/courts/{court_id}/approve")
def approve_court(court_id: str, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    db.court.update_one({"_id": oid(court_id)}, {"$set": {"status": "active"}})
    return {"ok": True}


@app.post("/admin/courts/{court_id}/reject")
def reject_court(court_id: str, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    db.court.update_one({"_id": oid(court_id)}, {"$set": {"status": "closed"}})
    return {"ok": True}


# -----------------------------
# Health & DB test
# -----------------------------
@app.get("/")
def read_root():
    return {"message": "Pickleball Social API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
