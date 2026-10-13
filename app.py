import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

APP_DIR = Path(__file__).parent
STORAGE_DIR = APP_DIR / "uploaded_files"
DB_PATH = APP_DIR / "files.db"
STORAGE_DIR.mkdir(exist_ok=True)

DURATIONS = {
    "1 hour": timedelta(hours=1),
    "1 day": timedelta(days=1),
    "1 week": timedelta(weeks=1),
    "Never expire": None,
}

def utc_now():
    return datetime.now(timezone.utc)

def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS shared_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                stored_name TEXT NOT NULL,
                original_name TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                size_bytes INTEGER NOT NULL
            )
        """)

def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def cleanup_expired_files():
    """Delete expired files and their database records."""
    now_iso = utc_now().isoformat()
    with connect_db() as conn:
        rows = conn.execute(
            "SELECT id, stored_name FROM shared_files "
            "WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now_iso,),
        ).fetchall()

        for row in rows:
            path = STORAGE_DIR / row["stored_name"]
            try:
                path.unlink(missing_ok=True)
            except OSError:
                # Keep the record so a later cleanup can retry.
                continue
            conn.execute("DELETE FROM shared_files WHERE id = ?", (row["id"],))

def save_upload(uploaded_file, duration_label):
    token = secrets.token_urlsafe(32)
    stored_name = secrets.token_hex(24)  # Never use the uploaded filename as a disk path.
    data = uploaded_file.getvalue()
    destination = STORAGE_DIR / stored_name
    destination.write_bytes(data)

    expires_at = None
    duration = DURATIONS[duration_label]
    if duration is not None:
        expires_at = (utc_now() + duration).isoformat()

    try:
        with connect_db() as conn:
            conn.execute(
                """INSERT INTO shared_files
                   (token_hash, stored_name, original_name, expires_at, created_at, size_bytes)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    hash_token(token),
                    stored_name,
                    Path(uploaded_file.name).name,
                    expires_at,
                    utc_now().isoformat(),
                    len(data),
                ),
            )
    except Exception:
        destination.unlink(missing_ok=True)
        raise

    return token, expires_at

def get_file_by_token(token):
    with connect_db() as conn:
        return conn.execute(
            "SELECT * FROM shared_files WHERE token_hash = ?",
            (hash_token(token),),
        ).fetchone()

def human_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"

st.set_page_config(page_title="Temporary File Sharing", page_icon="📁")
init_db()
cleanup_expired_files()

st.title("📁 Temporary File Sharing")
st.write("Upload a file, choose how long it should be available, and share the download link.")

# Route-style handling using a query parameter: ?token=...
params = st.query_params
download_token = params.get("token")

if download_token:
    record = get_file_by_token(download_token)

    if not record:
        st.error("This link is invalid, expired, or the file has been removed.")
        st.stop()

    if record["expires_at"]:
        expiry = datetime.fromisoformat(record["expires_at"])
        if utc_now() >= expiry:
            st.error("This download link has expired.")
            st.stop()

    file_path = STORAGE_DIR / record["stored_name"]
    if not file_path.is_file():
        st.error("The file is no longer available.")
        st.stop()

    st.subheader("Your file is ready")
    st.write(f"**Filename:** {record['original_name']}")
    st.write(f"**Size:** {human_size(record['size_bytes'])}")
    st.download_button(
        label="⬇️ Download file",
        data=file_path.read_bytes(),
        file_name=record["original_name"],
        mime="application/octet-stream",
        use_container_width=True,
    )
    st.divider()
    if st.button("Share another file"):
        st.query_params.clear()
        st.rerun()
    st.stop()

st.subheader("Upload a file")
uploaded_file = st.file_uploader("Choose a file")
duration_label = st.selectbox("Keep this file available for", list(DURATIONS.keys()))

# A modest default limit helps prevent accidental memory/disk exhaustion.
MAX_FILE_MB = 50
st.caption(f"Prototype upload limit: {MAX_FILE_MB} MB per file.")

if uploaded_file is not None:
    st.write(f"**Selected:** {uploaded_file.name} ({human_size(uploaded_file.size)})")
    if uploaded_file.size > MAX_FILE_MB * 1024 * 1024:
        st.error(f"Please upload a file smaller than {MAX_FILE_MB} MB.")
    elif st.button("Upload and generate link", type="primary"):
        try:
            token, expires_at = save_upload(uploaded_file, duration_label)
            share_url = f"{st.context.url.split('?')[0]}?token={token}"
            st.success("File uploaded successfully!")
            st.write("**Share this download link:**")
            st.code(share_url)
            st.link_button("Open download page", share_url)
            st.caption(
                "Expiry: " + (
                    datetime.fromisoformat(expires_at).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                    if expires_at else "Never expires"
                )
            )
            st.warning(
                "This starter version stores files on the server's local disk. "
                "For reliable public hosting, use persistent storage such as S3, "
                "and add scheduled cleanup, quotas, and abuse protection."
            )
        except Exception as exc:
            st.error(f"Could not save the file: {exc}")

with st.expander("About this prototype"):
    st.markdown(
        "- Expired files are cleaned up whenever the app is accessed.\n"
        "- For a public deployment, run cleanup on a schedule as well.\n"
        "- Anyone with a valid link can download the file.\n"
        "- Do not upload sensitive or confidential documents to this demo.\n"
        "- Never-expiring files remain until manually removed."
    )
