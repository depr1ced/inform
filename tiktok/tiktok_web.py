import json
import logging
import os
import secrets
from pathlib import Path
from urllib.parse import urlencode

import aiohttp
from aiohttp import web
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("tiktok-web")

CLIENT_KEY = os.getenv("TIKTOK_CLIENT_KEY", "")
CLIENT_SECRET = os.getenv("TIKTOK_CLIENT_SECRET", "")
PUBLIC_BASE_URL = os.getenv("TIKTOK_PUBLIC_BASE_URL", "https://depriced.online").rstrip("/")
REDIRECT_URI = os.getenv("TIKTOK_REDIRECT_URI", f"{PUBLIC_BASE_URL}/tiktok/callback")
SCOPES = "user.info.basic,video.list"

BASE_DIR = Path(__file__).resolve().parent
HTML_FILE = BASE_DIR / "tiktok.html"
TOKEN_FILE = BASE_DIR / "tiktok_tokens.json"

def render_page(status="not_connected", message="TikTok не подключён"):
    html = HTML_FILE.read_text(encoding="utf-8")
    classes = {"connected": "connected", "error": "error", "not_connected": ""}
    return html.replace("__STATUS_CLASS__", classes.get(status, "")).replace("__STATUS_TEXT__", message)

async def page(request):
    if TOKEN_FILE.exists():
        return web.Response(text=render_page("connected", "TikTok подключён"), content_type="text/html", charset="utf-8")
    return web.Response(text=render_page(), content_type="text/html", charset="utf-8")

async def login(request):
    if not CLIENT_KEY or not CLIENT_SECRET:
        return web.Response(text=render_page("error", "Не заполнены Client Key / Client Secret"), content_type="text/html", charset="utf-8", status=500)

    state = secrets.token_urlsafe(32)
    params = {
        "client_key": CLIENT_KEY,
        "scope": SCOPES,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    url = "https://www.tiktok.com/v2/auth/authorize/?" + urlencode(params)
    response = web.HTTPFound(url)
    response.set_cookie("tiktok_oauth_state", state, max_age=600, httponly=True, secure=True, samesite="Lax", path="/tiktok")
    return response

async def callback(request):
    error = request.query.get("error")
    error_description = request.query.get("error_description", "")
    if error:
        return web.Response(text=render_page("error", f"TikTok: {error_description or error}"), content_type="text/html", charset="utf-8", status=400)

    code = request.query.get("code", "")
    returned_state = request.query.get("state", "")
    saved_state = request.cookies.get("tiktok_oauth_state", "")

    if not code:
        return web.Response(text=render_page("error", "TikTok не вернул authorization code"), content_type="text/html", charset="utf-8", status=400)

    if not saved_state or not returned_state or not secrets.compare_digest(saved_state, returned_state):
        return web.Response(text=render_page("error", "Ошибка проверки OAuth state"), content_type="text/html", charset="utf-8", status=400)

    payload = {
        "client_key": CLIENT_KEY,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://open.tiktokapis.com/v2/oauth/token/",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            raw = await response.text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"error_description": raw}

            if response.status != 200:
                log.error("TikTok token exchange failed: %s", data)
                return web.Response(
                    text=render_page("error", data.get("error_description", "Ошибка получения TikTok token")),
                    content_type="text/html",
                    charset="utf-8",
                    status=400,
                )

    TOKEN_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("TikTok подключён. open_id=%s scopes=%s", data.get("open_id"), data.get("scope"))

    response = web.Response(
        text=render_page("connected", "TikTok успешно подключён"),
        content_type="text/html",
        charset="utf-8",
    )
    response.del_cookie("tiktok_oauth_state", path="/tiktok")
    return response

async def status(request):
    if not TOKEN_FILE.exists():
        return web.json_response({"connected": False})
    try:
        data = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
        return web.json_response({
            "connected": True,
            "open_id": data.get("open_id"),
            "scope": data.get("scope"),
            "expires_in": data.get("expires_in"),
            "refresh_expires_in": data.get("refresh_expires_in"),
        })
    except Exception:
        return web.json_response({"connected": False, "error": "invalid_token_file"})

def create_tiktok_web_app():
    app = web.Application()
    app.router.add_get("/tiktok", page)
    app.router.add_get("/tiktok/", page)
    app.router.add_get("/tiktok/login", login)
    app.router.add_get("/tiktok/callback", callback)
    app.router.add_get("/tiktok/status", status)
    return app

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    web.run_app(
        create_tiktok_web_app(),
        host=os.getenv("TIKTOK_WEB_HOST", "127.0.0.1"),
        port=int(os.getenv("TIKTOK_WEB_PORT", "8080")),
    )
