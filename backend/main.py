
import re
from typing import Literal
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from backend.auth import UserInfo, auth_router, get_current_user, get_optional_user
from database.database import Base, engine, get_db
from database.models import Student as StudentModel

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


# Create missing database tables when FastAPI starts.
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(auth_router)


# Pydantic schemas for request validation.
class StudentInput(BaseModel):
    name: str
    roll_no: str
    cgpa: float
    phone_no: str
    cnic: str


class StudentUpdate(BaseModel):
    name: str | None = None
    cgpa: float | None = None
    phone_no: str | None = None
    cnic: str | None = None


# Convert a database model to a JSON-friendly dictionary.
def student_to_dict(student: StudentModel):
    return {
        "name": student.name,
        "roll_no": student.roll_no,
        "cgpa": student.cgpa,
        "phone_no": student.phone_no,
        "cnic": student.cnic,
    }


def normalize(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]", "", value.casefold())


# Frontend
@app.get("/")
def read_root(current_user: UserInfo | None = Depends(get_optional_user)):
    if current_user is None:
        return RedirectResponse("/login")
    return FileResponse(FRONTEND_DIR / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/login")
def read_login(current_user: UserInfo | None = Depends(get_optional_user)):
    if current_user is not None:
        return RedirectResponse("/")
    return FileResponse(FRONTEND_DIR / "login.html", headers={"Cache-Control": "no-store"})


# CREATE: Add a student to PostgreSQL.
@app.post("/students", dependencies=[Depends(get_current_user)])
def create_student(
    student: StudentInput,
    db: Session = Depends(get_db),
):
    existing = db.query(StudentModel).filter(
        or_(
            StudentModel.roll_no == student.roll_no,
            StudentModel.cnic == student.cnic,
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="A student with this roll number or CNIC already exists",
        )

    new_student = StudentModel(**student.model_dump())

    try:
        db.add(new_student)
        db.commit()
        db.refresh(new_student)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A student with this roll number or CNIC already exists",
        )

    return {"student": student_to_dict(new_student)}


# READ: Get all students.
@app.get("/students", dependencies=[Depends(get_current_user)])
def list_students(db: Session = Depends(get_db)):
    all_students = db.query(StudentModel).all()

    return {
        "students": [student_to_dict(s) for s in all_students]
    }


# SEARCH: Search students by field or general search value.
@app.get("/students/search", dependencies=[Depends(get_current_user)])
def search_students(
    value: str,
    field: Literal["roll_no", "cgpa", "phone_no", "cnic", "name"] | None = None,
    db: Session = Depends(get_db),
):
    search_value = value.strip()

    if not search_value:
        raise HTTPException(
            status_code=422,
            detail="Search value cannot be empty",
        )

    all_students = db.query(StudentModel).all()

    if field == "cgpa":
        try:
            cgpa = float(search_value)
        except ValueError as error:
            raise HTTPException(
                status_code=422,
                detail="CGPA must be a number",
            ) from error

        matches = [s for s in all_students if s.cgpa == cgpa]

    elif field:
        normalized_value = (
            normalize(search_value)
            if field in {"phone_no", "cnic"}
            else search_value.casefold()
        )

        matches = []

        for student in all_students:
            student_value = getattr(student, field).strip().casefold()

            if field in {"phone_no", "cnic"}:
                student_value = normalize(student_value)

            if student_value == normalized_value:
                matches.append(student)

    else:
        normalized_value = search_value.casefold()
        normalized_digits = normalize(search_value)

        # Prefer exact roll number.
        exact_roll_matches = [
            s for s in all_students
            if s.roll_no.casefold() == normalized_value
        ]

        if exact_roll_matches:
            return {
                "students": [student_to_dict(s) for s in exact_roll_matches]
            }

        # Then exact name.
        exact_name_matches = [
            s for s in all_students
            if s.name.strip().casefold() == normalized_value
        ]

        if exact_name_matches:
            return {
                "students": [student_to_dict(s) for s in exact_name_matches]
            }

        # Then matching phone number or CNIC.
        normalized_phone_cnic_matches = [
            s for s in all_students
            if normalized_digits
            and (
                normalized_digits in normalize(s.phone_no)
                or normalized_digits in normalize(s.cnic)
            )
        ]

        if normalized_phone_cnic_matches:
            return {
                "students": [
                    student_to_dict(s)
                    for s in normalized_phone_cnic_matches
                ]
            }

        # Then exact CGPA.
        try:
            search_cgpa = float(search_value)
        except ValueError:
            search_cgpa = None

        if search_cgpa is not None:
            exact_cgpa_matches = [
                s for s in all_students if s.cgpa == search_cgpa
            ]

            if exact_cgpa_matches:
                return {
                    "students": [
                        student_to_dict(s) for s in exact_cgpa_matches
                    ]
                }

        # Finally, partial name, roll number, phone or CNIC search.
        matches = [
            s for s in all_students
            if normalized_value in s.name.casefold()
            or normalized_value in s.roll_no.casefold()
            or (
                normalized_digits
                and (
                    normalized_digits in normalize(s.phone_no)
                    or normalized_digits in normalize(s.cnic)
                )
            )
        ]

    return {"students": [student_to_dict(s) for s in matches]}


# READ: Get one student by roll number.
@app.get("/students/{roll_no}", dependencies=[Depends(get_current_user)])
def get_student(
    roll_no: str,
    db: Session = Depends(get_db),
):
    student = (
        db.query(StudentModel)
        .filter(StudentModel.roll_no == roll_no)
        .first()
    )

    if student is None:
        raise HTTPException(status_code=404, detail="Student not found")

    return {"student": student_to_dict(student)}


# DELETE: Remove a student from PostgreSQL.
@app.delete("/students/{roll_no}", dependencies=[Depends(get_current_user)])
def delete_student(
    roll_no: str,
    db: Session = Depends(get_db),
):
    student = (
        db.query(StudentModel)
        .filter(StudentModel.roll_no == roll_no)
        .first()
    )

    if student is None:
        raise HTTPException(status_code=404, detail="Student not found")

    db.delete(student)
    db.commit()

    return {
        "message": "Student deleted successfully",
        "roll_no": roll_no,
    }


# PATCH: Update only the fields supplied in the request.
@app.patch("/students/{roll_no}", dependencies=[Depends(get_current_user)])
def update_student(
    roll_no: str,
    updates: StudentUpdate,
    db: Session = Depends(get_db),
):
    student = (
        db.query(StudentModel)
        .filter(StudentModel.roll_no == roll_no)
        .first()
    )

    if student is None:
        raise HTTPException(status_code=404, detail="Student not found")

    update_data = updates.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(student, field, value)

    try:
        db.commit()
        db.refresh(student)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="The update conflicts with an existing database record",
        )

    return {"student": student_to_dict(student)}


# PUT: Replace a student's editable details.
@app.put("/students/{roll_no}", dependencies=[Depends(get_current_user)])
def replace_student(
    roll_no: str,
    student: StudentInput,
    db: Session = Depends(get_db),
):
    existing = (
        db.query(StudentModel)
        .filter(StudentModel.roll_no == roll_no)
        .first()
    )

    if existing is None:
        raise HTTPException(status_code=404, detail="Student not found")

    if student.roll_no != roll_no:
        raise HTTPException(
            status_code=400,
            detail="The body roll_no must match the URL roll_no",
        )

    existing.name = student.name
    existing.cgpa = student.cgpa
    existing.phone_no = student.phone_no
    existing.cnic = student.cnic

    try:
        db.commit()
        db.refresh(existing)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="The update conflicts with an existing database record",
        )

    return {"student": student_to_dict(existing)}
