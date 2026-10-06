# ========================
# backend/app/routes/lists.py
# CRUD Blacklist và Whitelist
# ========================

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import logging

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend.database.models import get_db, Blacklist, Whitelist
from backend.app.routes.auth import get_current_user

router = APIRouter(tags=["Lists Management"])
logger = logging.getLogger(__name__)


class ListItemRequest(BaseModel):
    value: str
    type: str  # "domain", "ip", "email"
    reason: Optional[str] = None


# ========================
# BLACKLIST
# ========================
@router.get("/blacklist", summary="Lấy danh sách đen")
def get_blacklist(page: int = 1, limit: int = 20, search: Optional[str] = None,
                  db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    query = db.query(Blacklist).order_by(Blacklist.added_at.desc())
    if search:
        query = query.filter(Blacklist.value.contains(search))
    total = query.count()
    items = query.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total,
        "data": [{"id": i.id, "value": i.value, "type": i.type,
                  "reason": i.reason, "added_at": i.added_at} for i in items]
    }


@router.post("/blacklist", summary="Thêm vào danh sách đen")
def add_blacklist(req: ListItemRequest, db: Session = Depends(get_db),
                  current_user=Depends(get_current_user)):
    if db.query(Blacklist).filter(Blacklist.value == req.value).first():
        raise HTTPException(400, "Giá trị đã tồn tại trong blacklist")
    item = Blacklist(value=req.value.lower(), type=req.type,
                     reason=req.reason, added_by=current_user.id)
    db.add(item)
    db.commit()
    logger.info(f"Thêm blacklist: {req.value} bởi {current_user.username}")
    return {"message": "Đã thêm vào danh sách đen", "id": item.id}


@router.put("/blacklist/{item_id}", summary="Sửa blacklist")
def update_blacklist(item_id: int, req: ListItemRequest,
                     db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    item = db.query(Blacklist).filter(Blacklist.id == item_id).first()
    if not item:
        raise HTTPException(404, "Không tìm thấy")
    item.value = req.value.lower()
    item.type = req.type
    item.reason = req.reason
    db.commit()
    return {"message": "Đã cập nhật"}


@router.delete("/blacklist/{item_id}", summary="Xóa khỏi blacklist")
def delete_blacklist(item_id: int, db: Session = Depends(get_db),
                     current_user=Depends(get_current_user)):
    item = db.query(Blacklist).filter(Blacklist.id == item_id).first()
    if not item:
        raise HTTPException(404, "Không tìm thấy")
    db.delete(item)
    db.commit()
    return {"message": "Đã xóa"}


# ========================
# WHITELIST
# ========================
@router.get("/whitelist", summary="Lấy danh sách trắng")
def get_whitelist(page: int = 1, limit: int = 20, search: Optional[str] = None,
                  db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    query = db.query(Whitelist).order_by(Whitelist.added_at.desc())
    if search:
        query = query.filter(Whitelist.value.contains(search))
    total = query.count()
    items = query.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total,
        "data": [{"id": i.id, "value": i.value, "type": i.type,
                  "reason": i.reason, "added_at": i.added_at} for i in items]
    }


@router.post("/whitelist", summary="Thêm vào danh sách trắng")
def add_whitelist(req: ListItemRequest, db: Session = Depends(get_db),
                  current_user=Depends(get_current_user)):
    if db.query(Whitelist).filter(Whitelist.value == req.value).first():
        raise HTTPException(400, "Giá trị đã tồn tại trong whitelist")
    item = Whitelist(value=req.value.lower(), type=req.type,
                     reason=req.reason, added_by=current_user.id)
    db.add(item)
    db.commit()
    return {"message": "Đã thêm vào danh sách trắng", "id": item.id}


@router.put("/whitelist/{item_id}", summary="Sửa whitelist")
def update_whitelist(item_id: int, req: ListItemRequest,
                     db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    item = db.query(Whitelist).filter(Whitelist.id == item_id).first()
    if not item:
        raise HTTPException(404, "Không tìm thấy")
    item.value = req.value.lower()
    item.type = req.type
    item.reason = req.reason
    db.commit()
    return {"message": "Đã cập nhật"}


@router.delete("/whitelist/{item_id}", summary="Xóa khỏi whitelist")
def delete_whitelist(item_id: int, db: Session = Depends(get_db),
                     current_user=Depends(get_current_user)):
    item = db.query(Whitelist).filter(Whitelist.id == item_id).first()
    if not item:
        raise HTTPException(404, "Không tìm thấy")
    db.delete(item)
    db.commit()
    return {"message": "Đã xóa"}


# ========================
# IMPORT BULK (Thêm nhiều cùng lúc)
# ========================
@router.post("/blacklist/bulk", summary="Thêm nhiều domain vào blacklist")
def bulk_add_blacklist(items: list[ListItemRequest], db: Session = Depends(get_db),
                       current_user=Depends(get_current_user)):
    added = 0
    skipped = 0
    for req in items:
        if not db.query(Blacklist).filter(Blacklist.value == req.value).first():
            db.add(Blacklist(value=req.value.lower(), type=req.type,
                             reason=req.reason, added_by=current_user.id))
            added += 1
        else:
            skipped += 1
    db.commit()
    return {"added": added, "skipped": skipped}