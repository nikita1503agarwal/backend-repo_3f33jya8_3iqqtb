"""
Database Schemas for Pickleball Social App

Each Pydantic model corresponds to a MongoDB collection. Collection name is the
lowercased class name (e.g., User -> "user").
"""

from __future__ import annotations
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, HttpUrl

# -----------------------------
# AUTH / USERS
# -----------------------------
class User(BaseModel):
    email: str = Field(..., description="Unique email for login")
    password_hash: str = Field(..., description="BCrypt hash of password")
    role: Literal["user", "admin"] = "user"
    display_name: str = Field(..., description="Public display name")
    avatar_url: Optional[HttpUrl] = Field(None, description="Profile photo URL")
    home_city: Optional[str] = None
    home_court_id: Optional[str] = Field(None, description="Court ID set as home court")
    dupr_score: Optional[float] = Field(None, ge=0)
    dupr_profile_url: Optional[HttpUrl] = None
    skill_level: Optional[Literal["Beginner", "Intermediate", "Advanced", "Pro"]] = None
    play_style: Optional[Literal["social", "competitive", "either"]] = None
    bio: Optional[str] = None
    favorites: List[str] = Field(default_factory=list, description="Court IDs the user favorited")

# -----------------------------
# COURTS
# -----------------------------
class Court(BaseModel):
    name: str
    address_street: str
    address_city: str
    address_state: str
    address_zip: str
    address_country: str
    latitude: float
    longitude: float
    number_of_courts: int
    indoor_outdoor: Literal["indoor", "outdoor"]
    hours: Optional[str] = None
    court_type: Literal["public", "private club", "pay to play", "HOA", "other"]
    surface_type: Optional[str] = None
    lighting: Literal["yes", "no"]
    busy_times: Optional[str] = None
    amenities: List[str] = Field(default_factory=list)
    website_url: Optional[HttpUrl] = None
    added_by_user_id: Optional[str] = None
    status: Literal["active", "pending review", "closed"] = "active"
    photos: List[str] = Field(default_factory=list, description="Photo URLs")

# -----------------------------
# REVIEWS
# -----------------------------
class Review(BaseModel):
    court_id: str
    user_id: str
    rating: int = Field(..., ge=1, le=5)
    text: Optional[str] = None

# -----------------------------
# POSTS (Community Feed)
# -----------------------------
class Post(BaseModel):
    author_id: str
    text: str
    photo_url: Optional[HttpUrl] = None
    court_id: Optional[str] = None
    likes: List[str] = Field(default_factory=list)

class Comment(BaseModel):
    post_id: str
    author_id: str
    text: str

# -----------------------------
# EVENTS
# -----------------------------
class Event(BaseModel):
    title: str
    court_id: str
    date: str  # ISO date (YYYY-MM-DD)
    start_time: str  # HH:MM
    end_time: str  # HH:MM
    preferred_min: Optional[float] = None
    preferred_max: Optional[float] = None
    max_players: int
    notes: Optional[str] = None
    organizer_id: str
    attendees: List[str] = Field(default_factory=list)
