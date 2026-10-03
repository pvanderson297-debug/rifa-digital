import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("DATA_DIR", BASE / "data"))
DATA.mkdir(parents=True, exist_ok=True)
RECEIPTS = DATA / "receipts"
PHOTOS = DATA / "photos"
RECEIPTS.mkdir(exist_ok=True)
PHOTOS.mkdir(exist_ok=True)
DB_PATH = DATA / "rifa.db"
SECRET = os.environ.get("RIFA_SECRET") or secrets.token_hex(32)
SESSION_TTL = 60 * 60 * 12
MAX_UPLOAD = 5 * 1024 * 1024

app = FastAPI(title="Rifa Digital")
app.mount("/assets", StaticFiles(directory=BASE / "static"), name="assets")


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${digest}"


def check_password(password, stored):
    salt, digest = stored.split("$", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
    return hmac.compare_digest(check, digest)


def sign(payload):
    body = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def unsign(token):
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expect = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None
    data = json.loads(body)
    if data.get("exp", 0) < time.time():
        return None
    return data


def init():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            title TEXT NOT NULL,
            prize TEXT NOT NULL,
            description TEXT NOT NULL,
            price_cents INTEGER NOT NULL,
            total INTEGER NOT NULL,
            draw_at TEXT,
            rules TEXT NOT NULL,
            organizer_name TEXT NOT NULL,
            organizer_phone TEXT NOT NULL,
            payment_instructions TEXT NOT NULL,
            reserve_minutes INTEGER NOT NULL,
            photo TEXT,
            sales_open INTEGER NOT NULL DEFAULT 1,
            winner_number INTEGER,
            winner_name TEXT,
            winner_public INTEGER NOT NULL DEFAULT 0,
            drawn_at TEXT,
            eligible_json TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ref TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            total_cents INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            paid_at TEXT,
            receipt TEXT,
            receipt_name TEXT,
            consent_public INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            number INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            reservation_id INTEGER,
            FOREIGN KEY (reservation_id) REFERENCES reservations(id)
        )
    """)
    row = conn.execute("SELECT id FROM settings WHERE id = 1").fetchone()
    if not row:
        draw_at = (now() + timedelta(days=7)).replace(microsecond=0).isoformat()
        conn.execute(
            """INSERT INTO settings (id, title, prize, description, price_cents, total, draw_at, rules,
               organizer_name, organizer_phone, payment_instructions, reserve_minutes, sales_open)
               VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (
                "Rifa da cesta de Natal",
                "Cesta completa + vale-compras de 50,00 €",
                "Escolha seus números, pague dentro do prazo e envie o comprovante. O número só é seu depois da confirmação do organizador.",
                500,
                100,
                draw_at,
                "1. Cada número custa 5,00 €.\n2. A reserva expira se o pagamento não for confirmado no prazo.\n3. O comprovante não confirma o pagamento sozinho.\n4. O sorteio usa apenas números pagos e é feito no servidor.\n5. O resultado não pode ser alterado depois de publicado.",
                "Organizador da rifa",
                "351910000000",
                "Transferência para o IBAN indicado pelo organizador. Envie o comprovante nesta página e avise no WhatsApp. O pagamento só vale depois da confirmação.",
                60,
            ),
        )
        for n in range(1, 101):
            conn.execute("INSERT INTO tickets (number, status) VALUES (?, 'available')", (n,))
    if not conn.execute("SELECT id FROM admin WHERE id = 1").fetchone():
        password = os.environ.get("RIFA_ADMIN_PASSWORD") or secrets.token_urlsafe(9)
        conn.execute("INSERT INTO admin (id, password_hash) VALUES (1, ?)", (hash_password(password),))
        (DATA / "ORGANIZER_PASSWORD.txt").write_text(password + "\n", encoding="utf-8")
    conn.close()


def release_expired(conn):
    due = conn.execute(
        "SELECT id FROM reservations WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?",
        (iso(now()),),
    ).fetchall()
    for row in due:
        conn.execute("UPDATE tickets SET status = 'available', reservation_id = NULL WHERE reservation_id = ?", (row["id"],))
        conn.execute("UPDATE reservations SET status = 'expired' WHERE id = ?", (row["id"],))


def settings_row(conn):
    return conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()


def public_raffle(conn):
    s = settings_row(conn)
    winner = None
    if s["winner_number"]:
        winner = {"number": s["winner_number"], "drawn_at": s["drawn_at"]}
        if s["winner_public"]:
            winner["name"] = s["winner_name"]
    return {
        "title": s["title"],
        "prize": s["prize"],
        "description": s["description"],
        "price_cents": s["price_cents"],
        "total": s["total"],
        "draw_at": s["draw_at"],
        "rules": s["rules"],
        "organizer_name": s["organizer_name"],
        "organizer_phone": s["organizer_phone"],
        "payment_instructions": s["payment_instructions"],
        "reserve_minutes": s["reserve_minutes"],
        "photo_url": "/api/photo" if s["photo"] else None,
        "sales_open": bool(s["sales_open"]) and not s["winner_number"],
        "drawn": bool(s["winner_number"]),
        "winner": winner,
    }


def admin_user(request: Request):
    token = request.cookies.get("rifa_session")
    data = unsign(token)
    if not data or data.get("role") != "admin":
        raise HTTPException(401, "Entre no painel para continuar.")
    return data


def money_cents(cents):
    euros = cents / 100
    whole, frac = f"{euros:.2f}".split(".")
    return f"{int(whole):,}".replace(",", ".") + f",{frac} €"


@app.on_event("startup")
def startup():
    init()


@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse(BASE / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/raffle")
def get_raffle():
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_expired(conn)
        payload = public_raffle(conn)
        conn.execute("COMMIT")
        return payload
    finally:
        conn.close()


@app.get("/api/numbers")
def get_numbers():
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_expired(conn)
        rows = conn.execute("SELECT number, status FROM tickets ORDER BY number").fetchall()
        conn.execute("COMMIT")
        return [{"number": r["number"], "status": r["status"]} for r in rows]
    finally:
        conn.close()


@app.get("/api/photo")
def photo():
    conn = db()
    row = conn.execute("SELECT photo FROM settings WHERE id = 1").fetchone()
    conn.close()
    if not row or not row["photo"]:
        raise HTTPException(404, "Sem foto")
    path = PHOTOS / row["photo"]
    if not path.exists():
        raise HTTPException(404, "Sem foto")
    return FileResponse(path)


@app.post("/api/reservations")
async def create_reservation(request: Request):
    body = await request.json()
    name = str(body.get("name") or "").strip()
    phone = "".join(ch for ch in str(body.get("phone") or "") if ch.isdigit())
    numbers = body.get("numbers") or []
    consent = 1 if body.get("consent_public") else 0
    if len(name) < 3:
        raise HTTPException(400, "Informe o nome completo.")
    if len(phone) < 10 or len(phone) > 15:
        raise HTTPException(400, "Informe o celular com código do país.")
    if not isinstance(numbers, list) or not numbers:
        raise HTTPException(400, "Escolha pelo menos um número.")
    numbers = sorted({int(n) for n in numbers})
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_expired(conn)
        s = settings_row(conn)
        if s["winner_number"] or not s["sales_open"]:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "As vendas estão encerradas.")
        if any(n < 1 or n > s["total"] for n in numbers):
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Número fora da rifa.")
        taken = []
        for n in numbers:
            row = conn.execute("SELECT status FROM tickets WHERE number = ?", (n,)).fetchone()
            if not row or row["status"] != "available":
                taken.append(n)
        if taken:
            conn.execute("ROLLBACK")
            raise HTTPException(409, f"Estes números já não estão livres: {', '.join(str(n) for n in taken)}")
        ref = "RF-" + secrets.token_hex(3).upper()
        created = now()
        expires = created + timedelta(minutes=int(s["reserve_minutes"]))
        total = s["price_cents"] * len(numbers)
        cur = conn.execute(
            """INSERT INTO reservations (ref, name, phone, total_cents, status, created_at, expires_at, consent_public)
               VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (ref, name, phone, total, iso(created), iso(expires), consent),
        )
        rid = cur.lastrowid
        for n in numbers:
            changed = conn.execute(
                "UPDATE tickets SET status = 'reserved', reservation_id = ? WHERE number = ? AND status = 'available'",
                (rid, n),
            ).rowcount
            if changed != 1:
                conn.execute("ROLLBACK")
                raise HTTPException(409, "Outra pessoa reservou um destes números agora.")
        conn.execute("COMMIT")
        return {
            "ref": ref,
            "name": name,
            "numbers": numbers,
            "total_cents": total,
            "total_label": money_cents(total),
            "expires_at": iso(expires),
            "reserve_minutes": s["reserve_minutes"],
            "payment_instructions": s["payment_instructions"],
            "organizer_phone": s["organizer_phone"],
            "status": "pending",
        }
    finally:
        conn.close()


@app.get("/api/reservations/{ref}")
def reservation_status(ref: str, phone: str):
    digits = "".join(ch for ch in phone if ch.isdigit())
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_expired(conn)
        row = conn.execute("SELECT * FROM reservations WHERE ref = ?", (ref,)).fetchone()
        if not row or row["phone"] != digits:
            conn.execute("ROLLBACK")
            raise HTTPException(404, "Reserva não encontrada.")
        nums = [r["number"] for r in conn.execute("SELECT number FROM tickets WHERE reservation_id = ? ORDER BY number", (row["id"],))]
        payload = {
            "ref": row["ref"],
            "status": row["status"],
            "numbers": nums,
            "total_label": money_cents(row["total_cents"]),
            "expires_at": row["expires_at"],
            "has_receipt": bool(row["receipt"]),
        }
        conn.execute("COMMIT")
        return payload
    finally:
        conn.close()


@app.post("/api/reservations/{ref}/receipt")
async def upload_receipt(ref: str, phone: str = Form(...), file: UploadFile = File(...)):
    digits = "".join(ch for ch in phone if ch.isdigit())
    content = await file.read()
    if not content or len(content) > MAX_UPLOAD:
        raise HTTPException(400, "Envie um comprovante de até 5 MB.")
    kind = (file.content_type or "").lower()
    if kind not in {"image/jpeg", "image/png", "image/webp", "application/pdf"}:
        raise HTTPException(400, "Use JPG, PNG, WEBP ou PDF.")
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "application/pdf": "pdf"}[kind]
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM reservations WHERE ref = ?", (ref,)).fetchone()
        if not row or row["phone"] != digits:
            conn.execute("ROLLBACK")
            raise HTTPException(404, "Reserva não encontrada.")
        if row["status"] != "pending":
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Esta reserva não está aguardando pagamento.")
        name = f"{ref}-{secrets.token_hex(4)}.{ext}"
        (RECEIPTS / name).write_bytes(content)
        conn.execute("UPDATE reservations SET receipt = ?, receipt_name = ? WHERE id = ?", (name, file.filename or name, row["id"]))
        conn.execute("COMMIT")
    finally:
        conn.close()
    return {"ok": True, "message": "Comprovante enviado. O pagamento só fica confirmado depois que o organizador verificar."}


@app.post("/api/admin/login")
async def login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    conn = db()
    row = conn.execute("SELECT password_hash FROM admin WHERE id = 1").fetchone()
    conn.close()
    if not row or not check_password(password, row["password_hash"]):
        raise HTTPException(401, "Senha incorreta.")
    token = sign({"role": "admin", "exp": int(time.time()) + SESSION_TTL})
    response = JSONResponse({"ok": True})
    response.set_cookie("rifa_session", token, httponly=True, samesite="lax", max_age=SESSION_TTL, secure=request.url.scheme == "https")
    return response


@app.post("/api/admin/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("rifa_session")
    return response


@app.get("/api/admin/me")
def me(request: Request):
    admin_user(request)
    return {"ok": True}


@app.get("/api/admin/overview")
def overview(request: Request):
    admin_user(request)
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_expired(conn)
        s = settings_row(conn)
        counts = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) n FROM tickets GROUP BY status")}
        received = conn.execute("SELECT COALESCE(SUM(total_cents), 0) c FROM reservations WHERE status = 'paid'").fetchone()["c"]
        rows = conn.execute("SELECT * FROM reservations ORDER BY id DESC").fetchall()
        items = []
        for row in rows:
            nums = [r["number"] for r in conn.execute("SELECT number FROM tickets WHERE reservation_id = ? ORDER BY number", (row["id"],))]
            items.append({
                "ref": row["ref"],
                "name": row["name"],
                "phone": row["phone"],
                "status": row["status"],
                "numbers": nums,
                "total_cents": row["total_cents"],
                "total_label": money_cents(row["total_cents"]),
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "paid_at": row["paid_at"],
                "has_receipt": bool(row["receipt"]),
                "consent_public": bool(row["consent_public"]),
            })
        conn.execute("COMMIT")
        payload = public_raffle(conn)
        payload.update({
            "counts": {
                "available": counts.get("available", 0),
                "reserved": counts.get("reserved", 0),
                "paid": counts.get("paid", 0),
            },
            "received_cents": received,
            "received_label": money_cents(received),
            "reservations": items,
            "eligible": json.loads(s["eligible_json"]) if s["eligible_json"] else None,
        })
        return payload
    finally:
        conn.close()


@app.put("/api/admin/raffle")
async def update_raffle(request: Request):
    admin_user(request)
    body = await request.json()
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        s = settings_row(conn)
        if s["winner_number"]:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "O sorteio já foi concluído e não pode ser alterado.")
        total = int(body.get("total") or s["total"])
        price = int(body.get("price_cents") or s["price_cents"])
        if total < 10 or total > 1000 or price < 50:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Use entre 10 e 1000 números e preço de pelo menos 0,50 €.")
        sold = conn.execute("SELECT COUNT(*) n FROM tickets WHERE status != 'available'").fetchone()["n"]
        if total != s["total"] and sold:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Não dá para mudar a quantidade depois de haver reservas.")
        conn.execute(
            """UPDATE settings SET title=?, prize=?, description=?, price_cents=?, total=?, draw_at=?, rules=?,
               organizer_name=?, organizer_phone=?, payment_instructions=?, reserve_minutes=?, sales_open=? WHERE id=1""",
            (
                str(body.get("title") or s["title"]).strip(),
                str(body.get("prize") or s["prize"]).strip(),
                str(body.get("description") or "").strip(),
                price,
                total,
                body.get("draw_at") or s["draw_at"],
                str(body.get("rules") or "").strip(),
                str(body.get("organizer_name") or "").strip(),
                "".join(ch for ch in str(body.get("organizer_phone") or "") if ch.isdigit()),
                str(body.get("payment_instructions") or "").strip(),
                max(5, int(body.get("reserve_minutes") or s["reserve_minutes"])),
                1 if body.get("sales_open", True) else 0,
            ),
        )
        if total != s["total"]:
            conn.execute("DELETE FROM tickets")
            for n in range(1, total + 1):
                conn.execute("INSERT INTO tickets (number, status) VALUES (?, 'available')", (n,))
        conn.execute("COMMIT")
        return public_raffle(conn)
    finally:
        conn.close()


@app.post("/api/admin/photo")
async def upload_photo(request: Request, file: UploadFile = File(...)):
    admin_user(request)
    content = await file.read()
    kind = (file.content_type or "").lower()
    if kind not in {"image/jpeg", "image/png", "image/webp"} or len(content) > MAX_UPLOAD:
        raise HTTPException(400, "Envie uma foto JPG, PNG ou WEBP de até 5 MB.")
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}[kind]
    name = f"prize-{secrets.token_hex(4)}.{ext}"
    (PHOTOS / name).write_bytes(content)
    conn = db()
    conn.execute("UPDATE settings SET photo = ? WHERE id = 1", (name,))
    conn.commit()
    conn.close()
    return {"photo_url": "/api/photo"}


@app.post("/api/admin/reservations/{ref}/confirm")
def confirm(ref: str, request: Request):
    admin_user(request)
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM reservations WHERE ref = ?", (ref,)).fetchone()
        if not row or row["status"] != "pending":
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Só dá para confirmar uma reserva pendente.")
        conn.execute("UPDATE reservations SET status = 'paid', paid_at = ? WHERE id = ?", (iso(now()), row["id"]))
        conn.execute("UPDATE tickets SET status = 'paid' WHERE reservation_id = ?", (row["id"],))
        conn.execute("COMMIT")
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/admin/reservations/{ref}/cancel")
def cancel(ref: str, request: Request):
    admin_user(request)
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM reservations WHERE ref = ?", (ref,)).fetchone()
        if not row or row["status"] not in {"pending", "paid"}:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Esta reserva não pode ser cancelada.")
        if settings_row(conn)["winner_number"]:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "O sorteio já foi concluído.")
        conn.execute("UPDATE tickets SET status = 'available', reservation_id = NULL WHERE reservation_id = ?", (row["id"],))
        conn.execute("UPDATE reservations SET status = 'cancelled' WHERE id = ?", (row["id"],))
        conn.execute("COMMIT")
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/admin/reservations/{ref}/receipt")
def receipt(ref: str, request: Request):
    admin_user(request)
    conn = db()
    row = conn.execute("SELECT receipt FROM reservations WHERE ref = ?", (ref,)).fetchone()
    conn.close()
    if not row or not row["receipt"]:
        raise HTTPException(404, "Sem comprovante.")
    path = RECEIPTS / row["receipt"]
    if not path.exists():
        raise HTTPException(404, "Sem comprovante.")
    return FileResponse(path)


@app.post("/api/admin/password")
async def change_password(request: Request):
    admin_user(request)
    body = await request.json()
    password = str(body.get("password") or "")
    if len(password) < 8:
        raise HTTPException(400, "Use uma senha com pelo menos 8 caracteres.")
    conn = db()
    conn.execute("UPDATE admin SET password_hash = ? WHERE id = 1", (hash_password(password),))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/admin/close-sales")
def close_sales(request: Request):
    admin_user(request)
    conn = db()
    conn.execute("UPDATE settings SET sales_open = 0 WHERE id = 1")
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/admin/draw")
async def draw(request: Request):
    admin_user(request)
    body = await request.json()
    if body.get("confirm") is not True:
        raise HTTPException(400, "Confirme o sorteio para continuar.")
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        release_expired(conn)
        s = settings_row(conn)
        if s["winner_number"]:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Este sorteio já foi concluído e não pode ser repetido.")
        if s["sales_open"]:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Encerre as vendas antes de sortear.")
        rows = conn.execute(
            """SELECT t.number, r.name, r.consent_public FROM tickets t
               JOIN reservations r ON r.id = t.reservation_id
               WHERE t.status = 'paid' ORDER BY t.number"""
        ).fetchall()
        if not rows:
            conn.execute("ROLLBACK")
            raise HTTPException(400, "Não há números pagos para sortear.")
        pick = rows[secrets.randbelow(len(rows))]
        eligible = [r["number"] for r in rows]
        conn.execute(
            """UPDATE settings SET winner_number=?, winner_name=?, winner_public=?, drawn_at=?, eligible_json=? WHERE id=1""",
            (pick["number"], pick["name"], pick["consent_public"], iso(now()), json.dumps(eligible)),
        )
        conn.execute("COMMIT")
        return {"number": pick["number"], "public_name": bool(pick["consent_public"]), "eligible": eligible}
    finally:
        conn.close()


@app.get("/api/admin/export.csv")
def export_csv(request: Request):
    admin_user(request)
    conn = db()
    rows = conn.execute("SELECT * FROM reservations ORDER BY id").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["referencia", "nome", "celular", "numeros", "total_euros", "estado", "criada_em", "expira_em", "paga_em", "comprovante"])
    for row in rows:
        nums = [str(r["number"]) for r in conn.execute("SELECT number FROM tickets WHERE reservation_id = ? ORDER BY number", (row["id"],))]
        writer.writerow([
            row["ref"], row["name"], row["phone"], " ".join(nums), f"{row['total_cents'] / 100:.2f}",
            row["status"], row["created_at"], row["expires_at"] or "", row["paid_at"] or "", "sim" if row["receipt"] else "nao",
        ])
    conn.close()
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=rifa.csv"})
