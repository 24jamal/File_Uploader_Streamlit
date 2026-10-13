import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import qrcode
from io import BytesIO
import streamlit as st
import requests

APP_DIR = Path(__file__).parent
STORAGE_DIR = APP_DIR / "uploaded_files"
DB_PATH = APP_DIR / "files.db"
STORAGE_DIR.mkdir(exist_ok=True)

DURATIONS = {
    "1 hour": timedelta(hours=1),
    "8 hours": timedelta(hours=8),
    "24 hours": timedelta(hours=24),

}

MAX_FILE_MB = 50


def utc_now():
    return datetime.now(timezone.utc)


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn



def get_ip_location():
    """Get the public IP and approximate location of the visitor."""
    try:
        response = requests.get(
            "https://ipapi.co/json/",
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("error"):
            return None

        return {
            "ip": data.get("ip", "Unavailable"),
            "city": data.get("city", "Unavailable"),
            "region": data.get("region", "Unavailable"),
            "country": data.get("country_name", "Unavailable"),
        }

    except (requests.RequestException, ValueError):
        return None


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
                size_bytes INTEGER NOT NULL,
                password_salt TEXT,
                password_hash TEXT
            )
        """)

        # Migrate an existing database without deleting its records.
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(shared_files)"
            ).fetchall()
        }

        if "password_salt" not in columns:
            conn.execute(
                "ALTER TABLE shared_files ADD COLUMN password_salt TEXT"
            )

        if "password_hash" not in columns:
            conn.execute(
                "ALTER TABLE shared_files ADD COLUMN password_hash TEXT"
            )


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password, salt=None):
    # A unique random salt is generated for each password.
    salt = salt or secrets.token_bytes(16)

    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )

    return salt.hex(), password_hash.hex()


def verify_password(password, salt_hex, expected_hash):
    salt = bytes.fromhex(salt_hex)

    _, actual_hash = hash_password(password, salt)

    return hmac.compare_digest(actual_hash, expected_hash)


def cleanup_expired_files():
    now_iso = utc_now().isoformat()

    with connect_db() as conn:
        rows = conn.execute(
            """
            SELECT id, stored_name
            FROM shared_files
            WHERE expires_at IS NOT NULL AND expires_at <= ?
            """,
            (now_iso,),
        ).fetchall()

        for row in rows:
            path = STORAGE_DIR / row["stored_name"]

            try:
                path.unlink(missing_ok=True)
            except OSError:
                # Keep the record so cleanup can retry later.
                continue

            conn.execute(
                "DELETE FROM shared_files WHERE id = ?",
                (row["id"],),
            )


def save_upload(uploaded_file, duration_label, password=None):
    token = secrets.token_urlsafe(32)
    stored_name = secrets.token_hex(24)

    data = uploaded_file.getvalue()
    destination = STORAGE_DIR / stored_name

    destination.write_bytes(data)

    expires_at = None
    duration = DURATIONS[duration_label]

    if duration is not None:
        expires_at = (utc_now() + duration).isoformat()

    password_salt = None
    password_hash = None

    if password:
        password_salt, password_hash = hash_password(password)

    try:
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO shared_files (
                    token_hash,
                    stored_name,
                    original_name,
                    expires_at,
                    created_at,
                    size_bytes,
                    password_salt,
                    password_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hash_token(token),
                    stored_name,
                    Path(uploaded_file.name).name,
                    expires_at,
                    utc_now().isoformat(),
                    len(data),
                    password_salt,
                    password_hash,
                ),
            )

    except Exception:
        destination.unlink(missing_ok=True)
        raise

    return token, expires_at


def get_file_by_token(token):
    with connect_db() as conn:
        return conn.execute(
            """
            SELECT *
            FROM shared_files
            WHERE token_hash = ?
            """,
            (hash_token(token),),
        ).fetchone()


def human_size(size):
    value = float(size)

    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"

        value /= 1024

    return f"{value:.1f} GB"


st.markdown(
    "<h2 style='text-align:center;'>🕷️ SpiderVault</h2>"
    "<p style='text-align:center; font-size:14px;'>Simple. Safe. Secure.</p>",
    unsafe_allow_html=True
)

init_db()
cleanup_expired_files()


st.markdown(
    """
    <p style="text-align: center; font-size: 14px;">
        Upload a file, choose its expiry and password settings,<br>
        and share the download link.
    </p>
    """,
    unsafe_allow_html=True
)


st.subheader("🌐 Visitor Information")

location = get_ip_location()

if location:
    col1, col2 = st.columns(2)

    with col1:
        st.metric("Public IP Address", location["ip"])
        st.write(f"**City:** {location['city']}")

    with col2:
        st.write(f"**State / Region:** {location['region']}")
        st.write(f"**Country:** {location['country']}")

    st.caption(
        "Location is approximate and based on public IP geolocation. "
        "A VPN or proxy may affect the result."
    )
else:
    st.info("Visitor IP and location are currently unavailable.")


params = st.query_params
download_token = params.get("token")

if download_token:
    record = get_file_by_token(download_token)

    if not record:
        st.error(
            "This link is invalid, expired, or the file has been removed."
        )
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

    # Password protection applies only when a password was configured.
    if record["password_hash"]:
        authorized_key = f"authorized_{hash_token(download_token)}"

        if not st.session_state.get(authorized_key, False):
            st.info("🔒 This file is password protected.")

            with st.form("download_password_form"):
                entered_password = st.text_input(
                    "Enter download password",
                    type="password",
                )

                submitted = st.form_submit_button(
                    "Unlock file",
                    type="primary",
                    use_container_width=True,
                )

            if submitted:
                if not entered_password:
                    st.error("Please enter the password.")

                elif verify_password(
                    entered_password,
                    record["password_salt"],
                    record["password_hash"],
                ):
                    st.session_state[authorized_key] = True
                    st.rerun()

                else:
                    st.error("Incorrect password. Please try again.")

            st.stop()

    st.success("File is available for download.")

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


# Upload page
st.subheader("Upload a file")

uploaded_file = st.file_uploader("Choose a file")

duration_label = st.selectbox(
    "Keep this file available for",
    list(DURATIONS.keys()),
)

password_option = st.selectbox(
    "Download password protection",
    ["No Password", "Password"],
)

password = None

if password_option == "Password":
    password = st.text_input(
        "Set a download password",
        type="password",
        help="The recipient must enter this password to download the file.",
    )

    st.caption(
        "Share the password separately from the download link."
    )

st.caption(f"Prototype upload limit: {MAX_FILE_MB} MB per file.")

if uploaded_file is not None:
    st.write(
        f"**Selected:** {uploaded_file.name} "
        f"({human_size(uploaded_file.size)})"
    )

    if uploaded_file.size > MAX_FILE_MB * 1024 * 1024:
        st.error(
            f"Please upload a file no larger than {MAX_FILE_MB} MB."
        )

    elif (
        password_option == "Password"
        and not password
    ):
        st.warning("Please set a password before uploading.")

    elif (
        password_option == "Password"
        and len(password) < 8
    ):
        st.warning("Use a password with at least 8 characters.")

    elif st.button(
        "Upload and generate link",
        type="primary",
    ):
        try:
            token, expires_at = save_upload(
                uploaded_file,
                duration_label,
                password if password_option == "Password" else None,
            )

            # Build the link using the current app URL.
            # Build the link using the current app URL.
            base_url = st.context.url.split("?")[0]
            share_url = f"{base_url}?token={token}"

            st.success("File uploaded successfully!")

            # Display the shareable URL
            st.subheader("Your Shareable Link")
            st.code(share_url)

            st.link_button("Open download page", share_url)

            # Generate the QR code from the same URL
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=10,
                border=4,
            )
            qr.add_data(share_url)
            qr.make(fit=True)

            qr_image = qr.make_image(
                fill_color="black",
                back_color="white",
            )

            # Convert QR code to PNG bytes
            qr_buffer = BytesIO()
            qr_image.save(qr_buffer, format="PNG")
            qr_bytes = qr_buffer.getvalue()

            # Display the QR code
            st.subheader("Scan QR Code to Open Link")
            st.image(qr_bytes, width=250)

            # Allow the user to save the QR code
            st.download_button(
                label="Download QR Code",
                data=qr_bytes,
                file_name="file_sharing_qr.png",
                mime="image/png",
            )

            if expires_at:
                expiry_display = (
                    datetime.fromisoformat(expires_at)
                    .astimezone()
                    .strftime("%Y-%m-%d %H:%M:%S %Z")
                )
            else:
                expiry_display = "Never expires"

            st.caption(f"Expiry: {expiry_display}")

            if password_option == "Password":
                st.info(
                    "🔒 Password protection is enabled. "
                    "Send the password to the recipient separately."
                )
            else:
                st.info(
                    "Anyone with the valid link can download this file."
                )



        except Exception:
            st.error(
                "Could not save the file. Please try again."
            )


with st.expander("About this prototype"):
    st.markdown(
        "- Expired files are cleaned up whenever the app is accessed.\n"
        "- Public hosting should use scheduled cleanup.\n"
        "- Password-protected links require the correct password.\n"
        "- Passwords are stored as salted hashes, not plaintext.\n"
        "- Anyone with a non-password-protected valid link can download.\n"
        "- Never-expiring files remain until manually removed.\n"
        "- Do not upload sensitive documents to this prototype."
    )