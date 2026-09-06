import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.config import get_settings
from app.database import get_db
from app.models import Project, SourceType, User
from app.schemas import ProjectCreateGit, ProjectCreateUpload, ProjectOut
from app.services.storage import (
    cleanup_path,
    make_project_dir,
    save_upload,
)
from app.services.validation import ValidationError, safe_extract_zip, validate_git_url

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(Project).filter(Project.owner_id == current_user.id).all()


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project_git(
    payload: ProjectCreateGit,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        safe_url = validate_git_url(payload.source_ref)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    project = Project(
        owner_id=current_user.id,
        name=payload.name,
        source_type=SourceType.git,
        source_ref=safe_url,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.post("/upload", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project_upload(
    name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    settings = get_settings()
    try:
        upload_path = save_upload(
            file,
            settings.uploads_dir,
            settings.max_upload_size_bytes,
        )
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    project = Project(
        owner_id=current_user.id,
        name=name,
        source_type=SourceType.upload,
        source_ref=upload_path,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    # Extract immediately into a project-scoped directory.
    extract_dir = make_project_dir(settings.uploads_dir, str(project.id))
    try:
        safe_extract_zip(
            upload_path,
            extract_dir,
            settings.max_zip_entries,
            settings.max_extracted_size_bytes,
        )
    except (HTTPException, ValidationError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        cleanup_path(upload_path)
        db.delete(project)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    return project


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id,
    ).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.owner_id == current_user.id,
    ).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    settings = get_settings()
    if project.source_type == SourceType.upload:
        cleanup_path(project.source_ref)
        cleanup_path(make_project_dir(settings.uploads_dir, str(project.id)))

    db.delete(project)
    db.commit()
    return None
