"""
Hospital Management System API
FastAPI + SQLModel + SQLite

Features:
- Admin: Manage staff, doctors, beds
- Management: Manage patients, assign resources
- Real-time patient monitoring with webhooks
- JWT Authentication with RBAC
- Password hashing
"""

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import SQLModel, Field, Session, create_engine, select, Relationship
from typing import Optional, List
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt
from pydantic import BaseModel, EmailStr
from enum import Enum
import httpx


# ============= Configuration =============
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

DATABASE_URL = "sqlite:///./hospital.db"
engine = create_engine(DATABASE_URL, echo=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ============= Enums =============
class UserRole(str, Enum):
    ADMIN = "admin"
    MANAGEMENT = "management"

class DoctorStatus(str, Enum):
    AVAILABLE = "available"
    BUSY = "busy"
    ON_LEAVE = "on_leave"

class PatientStatus(str, Enum):
    ADMITTED = "admitted"
    DISCHARGED = "discharged"
    CRITICAL = "critical"

class VitalStatus(str, Enum):
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"

# ============= Database Models =============
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    full_name: str
    hashed_password: str
    role: UserRole
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    registered_patients: List["Patient"] = Relationship(back_populates="registered_by_user")
    webhook_subscriptions: List["WebhookSubscription"] = Relationship(back_populates="user")

class Doctor(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    full_name: str
    specialization: str
    phone: str
    email: str = Field(unique=True)
    status: DoctorStatus = DoctorStatus.AVAILABLE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    patients: List["Patient"] = Relationship(back_populates="doctor")

class Bed(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    bed_number: str = Field(unique=True, index=True)
    ward: str
    is_available: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    patient: Optional["Patient"] = Relationship(back_populates="bed")

class Patient(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    full_name: str
    age: int
    gender: str
    phone: str
    emergency_contact: str
    condition: str
    disease_reason: str
    status: PatientStatus = PatientStatus.ADMITTED
    admitted_at: datetime = Field(default_factory=datetime.utcnow)
    discharged_at: Optional[datetime] = None
    
    # Foreign Keys
    bed_id: Optional[int] = Field(default=None, foreign_key="bed.id")
    doctor_id: Optional[int] = Field(default=None, foreign_key="doctor.id")
    registered_by: int = Field(foreign_key="user.id")
    
    # Relationships
    bed: Optional[Bed] = Relationship(back_populates="patient")
    doctor: Optional[Doctor] = Relationship(back_populates="patients")
    registered_by_user: User = Relationship(back_populates="registered_patients")
    vital_signs: List["VitalSign"] = Relationship(back_populates="patient")

class VitalSign(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    patient_id: int = Field(foreign_key="patient.id")
    heart_rate: int
    oxygen_level: int
    temperature: Optional[float] = None
    blood_pressure: Optional[str] = None
    status: VitalStatus = VitalStatus.NORMAL
    recorded_at: datetime = Field(default_factory=datetime.utcnow)
    alert_sent: bool = False
    
    # Relationships
    patient: Patient = Relationship(back_populates="vital_signs")

class WebhookSubscription(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    webhook_url: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships
    user: User = Relationship(back_populates="webhook_subscriptions")

class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int
    action: str
    entity_type: str
    entity_id: int
    details: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# ============= Pydantic Schemas =============
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: UserRole

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class DoctorCreate(BaseModel):
    full_name: str
    specialization: str
    phone: str
    email: EmailStr

class DoctorUpdate(BaseModel):
    status: Optional[DoctorStatus] = None
    full_name: Optional[str] = None
    specialization: Optional[str] = None
    phone: Optional[str] = None

class BedCreate(BaseModel):
    bed_number: str
    ward: str

class PatientCreate(BaseModel):
    full_name: str
    age: int
    gender: str
    phone: str
    emergency_contact: str
    condition: str
    disease_reason: str
    bed_id: Optional[int] = None
    doctor_id: Optional[int] = None

class PatientUpdate(BaseModel):
    condition: Optional[str] = None
    disease_reason: Optional[str] = None
    bed_id: Optional[int] = None
    doctor_id: Optional[int] = None
    status: Optional[PatientStatus] = None

class VitalSignCreate(BaseModel):
    patient_id: int
    heart_rate: int
    oxygen_level: int
    temperature: Optional[float] = None
    blood_pressure: Optional[str] = None

class WebhookSubscriptionCreate(BaseModel):
    webhook_url: str

class DashboardStats(BaseModel):
    total_patients: int
    admitted_patients: int
    critical_patients: int
    available_beds: int
    total_beds: int
    available_doctors: int
    total_doctors: int

# ============= Helper Functions =============
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_session():
    with Session(engine) as session:
        yield session

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: Session = Depends(get_session)
) -> User:
    token = credentials.credentials
    payload = decode_token(token)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user

def require_role(allowed_roles: List[UserRole]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in allowed_roles]}"
            )
        return current_user
    return role_checker

def log_action(session: Session, user_id: int, action: str, entity_type: str, entity_id: int, details: str):
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details
    )
    session.add(audit_log)
    session.commit()

def check_vital_signs(heart_rate: int, oxygen_level: int) -> VitalStatus:
    """Check if vital signs are normal, warning, or critical"""
    critical = False
    warning = False
    
    # Heart rate checks (normal: 60-100 bpm)
    if heart_rate < 40 or heart_rate > 140:
        critical = True
    elif heart_rate < 60 or heart_rate > 100:
        warning = True
    
    # Oxygen level checks (normal: 95-100%)
    if oxygen_level < 85:
        critical = True
    elif oxygen_level < 95:
        warning = True
    
    if critical:
        return VitalStatus.CRITICAL
    elif warning:
        return VitalStatus.WARNING
    else:
        return VitalStatus.NORMAL

async def send_webhook_alerts(session: Session, patient: Patient, vital_sign: VitalSign):
    """Send webhook alerts to all active management users"""
    webhooks = session.exec(
        select(WebhookSubscription).where(WebhookSubscription.is_active == True)
    ).all()
    
    alert_data = {
        "alert_type": vital_sign.status.value,
        "patient_id": patient.id,
        "patient_name": patient.full_name,
        "condition": patient.condition,
        "heart_rate": vital_sign.heart_rate,
        "oxygen_level": vital_sign.oxygen_level,
        "timestamp": vital_sign.recorded_at.isoformat(),
        "message": f"ALERT: Patient {patient.full_name} has {vital_sign.status.value} vital signs!"
    }
    
    async with httpx.AsyncClient() as client:
        for webhook in webhooks:
            try:
                await client.post(webhook.webhook_url, json=alert_data, timeout=5.0)
            except Exception as e:
                print(f"Failed to send webhook to {webhook.webhook_url}: {e}")

# ============= FastAPI App =============
app = FastAPI(
    title="Hospital Management System API",
    description="Real-time hospital management with patient monitoring",
    version="1.0.0"
)

origins = [
    "http://localhost:3000",  # your Next.js app
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,           # allows requests from these origins
    allow_credentials=True,
    allow_methods=["*"],             # allows all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],             # allows all headers
)


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    
    # Create default admin if not exists
    with Session(engine) as session:
        admin = session.exec(select(User).where(User.email == "admin@hospital.com")).first()
        if not admin:
            admin = User(
                email="admin@hospital.com",
                full_name="System Administrator",
                hashed_password=hash_password("admin123"),
                role=UserRole.ADMIN
            )
            session.add(admin)
            session.commit()
            print("✅ Default admin created: admin@hospital.com / admin123")

# ============= Authentication Endpoints =============
@app.post("/api/auth/register", response_model=dict, tags=["Authentication"])
def register_user(
    user_data: UserCreate,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Register new management staff"""
    existing = session.exec(select(User).where(User.email == user_data.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        role=user_data.role
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    
    log_action(session, current_user.id, "CREATE", "User", user.id, f"Created user: {user.email}")
    
    return {"message": "User registered successfully", "user_id": user.id}

@app.post("/api/auth/login", response_model=Token, tags=["Authentication"])
def login(user_data: UserLogin, session: Session = Depends(get_session)):
    """Login endpoint for all users"""
    user = session.exec(select(User).where(User.email == user_data.email)).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is inactive")
    
    access_token = create_access_token({"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me", tags=["Authentication"])
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role
    }

# ============= User Management (Admin Only) =============
@app.get("/api/users", tags=["User Management"])
def list_users(
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: List all users"""
    users = session.exec(select(User)).all()
    return users

@app.delete("/api/users/{user_id}", tags=["User Management"])
def delete_user(
    user_id: int,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Delete a user"""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    session.delete(user)
    session.commit()
    
    log_action(session, current_user.id, "DELETE", "User", user_id, f"Deleted user: {user.email}")
    
    return {"message": "User deleted successfully"}

# ============= Doctor Management =============
@app.post("/api/doctors", tags=["Doctors"])
def create_doctor(
    doctor_data: DoctorCreate,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Add a new doctor"""
    existing = session.exec(select(Doctor).where(Doctor.email == doctor_data.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Doctor with this email already exists")
    
    doctor = Doctor(**doctor_data.dict())
    session.add(doctor)
    session.commit()
    session.refresh(doctor)
    
    log_action(session, current_user.id, "CREATE", "Doctor", doctor.id, f"Created doctor: {doctor.full_name}")
    
    return doctor

@app.get("/api/doctors", tags=["Doctors"])
def list_doctors(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """List all doctors"""
    doctors = session.exec(select(Doctor)).all()
    return doctors

@app.get("/api/doctors/{doctor_id}", tags=["Doctors"])
def get_doctor(
    doctor_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Get doctor details"""
    doctor = session.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return doctor

@app.patch("/api/doctors/{doctor_id}", tags=["Doctors"])
def update_doctor(
    doctor_id: int,
    doctor_data: DoctorUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Management and Admin: Update doctor status and details"""
    doctor = session.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    update_data = doctor_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(doctor, key, value)
    
    doctor.updated_at = datetime.utcnow()
    session.add(doctor)
    session.commit()
    session.refresh(doctor)
    
    log_action(session, current_user.id, "UPDATE", "Doctor", doctor_id, f"Updated doctor: {doctor.full_name}")
    
    return doctor

@app.delete("/api/doctors/{doctor_id}", tags=["Doctors"])
def delete_doctor(
    doctor_id: int,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Delete a doctor"""
    doctor = session.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Check if doctor has active patients
    active_patients = session.exec(
        select(Patient).where(
            Patient.doctor_id == doctor_id,
            Patient.status == PatientStatus.ADMITTED
        )
    ).all()
    
    if active_patients:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete doctor with active patients. Reassign patients first."
        )
    
    session.delete(doctor)
    session.commit()
    
    log_action(session, current_user.id, "DELETE", "Doctor", doctor_id, f"Deleted doctor: {doctor.full_name}")
    
    return {"message": "Doctor deleted successfully"}

# ============= Bed Management =============
@app.post("/api/beds", tags=["Beds"])
def create_bed(
    bed_data: BedCreate,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Add a new bed"""
    existing = session.exec(select(Bed).where(Bed.bed_number == bed_data.bed_number)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Bed number already exists")
    
    bed = Bed(**bed_data.dict())
    session.add(bed)
    session.commit()
    session.refresh(bed)
    
    log_action(session, current_user.id, "CREATE", "Bed", bed.id, f"Created bed: {bed.bed_number}")
    
    return bed

@app.get("/api/beds", tags=["Beds"])
def list_beds(
    available_only: bool = False,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """List all beds"""
    query = select(Bed)
    if available_only:
        query = query.where(Bed.is_available == True)
    beds = session.exec(query).all()
    return beds

@app.delete("/api/beds/{bed_id}", tags=["Beds"])
def delete_bed(
    bed_id: int,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Delete a bed"""
    bed = session.get(Bed, bed_id)
    if not bed:
        raise HTTPException(status_code=404, detail="Bed not found")
    
    if not bed.is_available:
        raise HTTPException(status_code=400, detail="Cannot delete occupied bed")
    
    session.delete(bed)
    session.commit()
    
    log_action(session, current_user.id, "DELETE", "Bed", bed_id, f"Deleted bed: {bed.bed_number}")
    
    return {"message": "Bed deleted successfully"}

# ============= Patient Management =============
@app.post("/api/patients", tags=["Patients"])
def create_patient(
    patient_data: PatientCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Management and Admin: Register a new patient"""
    # Validate bed if provided
    if patient_data.bed_id:
        bed = session.get(Bed, patient_data.bed_id)
        if not bed:
            raise HTTPException(status_code=404, detail="Bed not found")
        if not bed.is_available:
            raise HTTPException(status_code=400, detail="Bed is not available")
        bed.is_available = False
    
    # Validate and update doctor if provided
    if patient_data.doctor_id:
        doctor = session.get(Doctor, patient_data.doctor_id)
        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")
        if doctor.status == DoctorStatus.ON_LEAVE:
            raise HTTPException(status_code=400, detail="Doctor is on leave")
        doctor.status = DoctorStatus.BUSY
    
    patient = Patient(
        **patient_data.dict(),
        registered_by=current_user.id
    )
    session.add(patient)
    session.commit()
    session.refresh(patient)
    
    log_action(session, current_user.id, "CREATE", "Patient", patient.id, f"Registered patient: {patient.full_name}")
    
    return patient

@app.get("/api/patients", tags=["Patients"])
def list_patients(
    status: Optional[PatientStatus] = None,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """List all patients"""
    query = select(Patient)
    if status:
        query = query.where(Patient.status == status)
    patients = session.exec(query).all()
    return patients

@app.get("/api/patients/{patient_id}", tags=["Patients"])
def get_patient(
    patient_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Get patient details"""
    patient = session.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patient

@app.patch("/api/patients/{patient_id}", tags=["Patients"])
def update_patient(
    patient_id: int,
    patient_data: PatientUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Management and Admin: Update patient details"""
    patient = session.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    update_data = patient_data.dict(exclude_unset=True)
    
    # Handle bed assignment
    if "bed_id" in update_data and update_data["bed_id"] != patient.bed_id:
        # Release old bed
        if patient.bed_id:
            old_bed = session.get(Bed, patient.bed_id)
            if old_bed:
                old_bed.is_available = True
        
        # Assign new bed
        if update_data["bed_id"]:
            new_bed = session.get(Bed, update_data["bed_id"])
            if not new_bed:
                raise HTTPException(status_code=404, detail="Bed not found")
            if not new_bed.is_available:
                raise HTTPException(status_code=400, detail="Bed is not available")
            new_bed.is_available = False
    
    # Handle doctor assignment
    if "doctor_id" in update_data and update_data["doctor_id"] != patient.doctor_id:
        # Release old doctor
        if patient.doctor_id:
            old_doctor = session.get(Doctor, patient.doctor_id)
            if old_doctor and old_doctor.status == DoctorStatus.BUSY:
                # Check if doctor has other patients
                other_patients = session.exec(
                    select(Patient).where(
                        Patient.doctor_id == patient.doctor_id,
                        Patient.id != patient_id,
                        Patient.status == PatientStatus.ADMITTED
                    )
                ).first()
                if not other_patients:
                    old_doctor.status = DoctorStatus.AVAILABLE
        
        # Assign new doctor
        if update_data["doctor_id"]:
            new_doctor = session.get(Doctor, update_data["doctor_id"])
            if not new_doctor:
                raise HTTPException(status_code=404, detail="Doctor not found")
            if new_doctor.status == DoctorStatus.ON_LEAVE:
                raise HTTPException(status_code=400, detail="Doctor is on leave")
            new_doctor.status = DoctorStatus.BUSY
    
    # Handle discharge
    if "status" in update_data and update_data["status"] == PatientStatus.DISCHARGED:
        patient.discharged_at = datetime.utcnow()
        
        # Release bed
        if patient.bed_id:
            bed = session.get(Bed, patient.bed_id)
            if bed:
                bed.is_available = True
        
        # Release doctor
        if patient.doctor_id:
            doctor = session.get(Doctor, patient.doctor_id)
            if doctor:
                # Check if doctor has other patients
                other_patients = session.exec(
                    select(Patient).where(
                        Patient.doctor_id == patient.doctor_id,
                        Patient.id != patient_id,
                        Patient.status == PatientStatus.ADMITTED
                    )
                ).first()
                if not other_patients:
                    doctor.status = DoctorStatus.AVAILABLE
    
    for key, value in update_data.items():
        setattr(patient, key, value)
    
    session.add(patient)
    session.commit()
    session.refresh(patient)
    
    log_action(session, current_user.id, "UPDATE", "Patient", patient_id, f"Updated patient: {patient.full_name}")
    
    return patient

# ============= Vital Signs & Monitoring =============
@app.post("/api/vitals", tags=["Vital Signs"])
async def record_vital_signs(
    vital_data: VitalSignCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """Receive real-time vital signs from sensors (no auth required for IoT devices)"""
    patient = session.get(Patient, vital_data.patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    if patient.status != PatientStatus.ADMITTED:
        raise HTTPException(status_code=400, detail="Patient is not admitted")
    
    # Check vital signs status
    vital_status = check_vital_signs(vital_data.heart_rate, vital_data.oxygen_level)
    
    vital_sign = VitalSign(
        **vital_data.dict(),
        status=vital_status
    )
    session.add(vital_sign)
    
    # Update patient status if critical
    if vital_status == VitalStatus.CRITICAL:
        patient.status = PatientStatus.CRITICAL
        session.add(patient)
    
    session.commit()
    session.refresh(vital_sign)
    
    # Send alerts if abnormal
    if vital_status in [VitalStatus.WARNING, VitalStatus.CRITICAL]:
        background_tasks.add_task(send_webhook_alerts, session, patient, vital_sign)
        vital_sign.alert_sent = True
        session.add(vital_sign)
        session.commit()
    
    return {
        "message": "Vital signs recorded",
        "status": vital_status,
        "alert_sent": vital_sign.alert_sent
    }

@app.get("/api/patients/{patient_id}/vitals", tags=["Vital Signs"])
def get_patient_vitals(
    patient_id: int,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Get vital signs history for a patient"""
    patient = session.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    vitals = session.exec(
        select(VitalSign)
        .where(VitalSign.patient_id == patient_id)
        .order_by(VitalSign.recorded_at.desc())
        .limit(limit)
    ).all()
    
    return vitals

@app.get("/api/vitals/alerts", tags=["Vital Signs"])
def get_active_alerts(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Get all active alerts (warning or critical)"""
    alerts = session.exec(
        select(VitalSign)
        .where(VitalSign.status.in_([VitalStatus.WARNING, VitalStatus.CRITICAL]))
        .order_by(VitalSign.recorded_at.desc())
        .limit(100)
    ).all()
    
    return alerts

# ============= Webhook Management =============
@app.post("/api/webhooks", tags=["Webhooks"])
def subscribe_webhook(
    webhook_data: WebhookSubscriptionCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Subscribe to vital sign alerts via webhook"""
    webhook = WebhookSubscription(
        user_id=current_user.id,
        webhook_url=webhook_data.webhook_url
    )
    session.add(webhook)
    session.commit()
    session.refresh(webhook)
    
    return webhook

@app.get("/api/webhooks", tags=["Webhooks"])
def list_webhooks(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """List user's webhook subscriptions"""
    webhooks = session.exec(
        select(WebhookSubscription).where(WebhookSubscription.user_id == current_user.id)
    ).all()
    return webhooks

@app.delete("/api/webhooks/{webhook_id}", tags=["Webhooks"])
def delete_webhook(
    webhook_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Delete a webhook subscription"""
    webhook = session.get(WebhookSubscription, webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    if webhook.user_id != current_user.id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    session.delete(webhook)
    session.commit()
    
    return {"message": "Webhook deleted successfully"}

# ============= Dashboard & Analytics =============
@app.get("/api/dashboard/stats", response_model=DashboardStats, tags=["Dashboard"])
def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Get dashboard statistics"""
    total_patients = session.exec(select(Patient)).all()
    admitted_patients = session.exec(
        select(Patient).where(Patient.status == PatientStatus.ADMITTED)
    ).all()
    critical_patients = session.exec(
        select(Patient).where(Patient.status == PatientStatus.CRITICAL)
    ).all()
    
    all_beds = session.exec(select(Bed)).all()
    available_beds = session.exec(select(Bed).where(Bed.is_available == True)).all()
    
    all_doctors = session.exec(select(Doctor)).all()
    available_doctors = session.exec(
        select(Doctor).where(Doctor.status == DoctorStatus.AVAILABLE)
    ).all()
    
    return DashboardStats(
        total_patients=len(total_patients),
        admitted_patients=len(admitted_patients),
        critical_patients=len(critical_patients),
        available_beds=len(available_beds),
        total_beds=len(all_beds),
        available_doctors=len(available_doctors),
        total_doctors=len(all_doctors)
    )

@app.get("/api/audit-logs", tags=["Audit"])
def get_audit_logs(
    limit: int = 100,
    current_user: User = Depends(require_role([UserRole.ADMIN])),
    session: Session = Depends(get_session)
):
    """Admin only: Get audit logs"""
    logs = session.exec(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    ).all()
    return logs

# ============= Health Check =============
@app.get("/", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "Hospital Management System API",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)