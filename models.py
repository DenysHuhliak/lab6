from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class User:
    id: int
    full_name: str
    email: str
    role: str
    password_hash: Optional[str] = None
    is_verified: int = 0
    is_blocked: int = 0
    failed_login_attempts: int = 0
    locked_until: Optional[str] = None
    two_factor_enabled: int = 0
    oauth_provider: Optional[str] = None
    oauth_sub: Optional[str] = None

    def to_dict(self):
        data = asdict(self)
        data.pop("password_hash", None)
        return data


@dataclass
class Floor:
    id: int
    floor_number: int
    svg_file_path: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Room:
    id: int
    floor_id: int
    room_number: str
    capacity: int
    equipment_description: str
    svg_polygon_id: str
    is_active: int
    floor_number: Optional[int] = 3

    def to_dict(self):
        return asdict(self)


@dataclass
class Booking:
    id: int
    room_id: int
    user_id: int
    purpose: str
    start_time: str
    end_time: str
    status: str
    created_at: str
    reminder_sent: int = 0
    room_number: Optional[str] = None
    teacher_name: Optional[str] = None
    email: Optional[str] = None

    def to_dict(self):
        return asdict(self)