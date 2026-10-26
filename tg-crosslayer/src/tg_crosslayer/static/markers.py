"""Version-independent indicators. Indicators alone never prove provenance."""
import re

TG_PATH_MARKERS = (
    "org/telegram/messenger", "org/telegram/tgnet", "org/telegram/ui",
    "tlrpc", "connectionsmanager", "messagescontroller", "nativebytebuffer",
)
TG_TEXT_MARKERS = (
    "org.telegram.messenger", "org.telegram.tgnet", "tlrpc", "connectionsmanager",
    "messagescontroller", "mtproto", "libtmessages",
)
CAPABILITY_MARKERS = {
    "usb_uvc": ("libuvc", "uvc_camera", "usbdeviceconnection", "usbhostmanager"),
    "rtc": ("dingrtc", "agora", "webrtc", "rtcengine"),
    "media": ("ffmpeg", "libyuv", "mediacodec", "videoprocessor"),
    "protection": ("shield", "jiagu", "shellapplication"),
    "environment": ("isdebuggerconnected", "isrooted", "detectemulator", "rootcheck"),
    "services": ("bugly", "umeng", "xinstall", "clink"),
    "web_h5": ("android.webkit.webview", "uni-jsframework", "window.location"),
    "proxy": ("mtprotoproxy", "socks5", "proxysettings"),
    "config": ("remoteconfig", "serverlist", "configurl", "bootstrap"),
}
TEXT_SUFFIXES = frozenset({".xml", ".json", ".txt", ".html", ".htm", ".js", ".properties", ".conf", ".ini", ".java"})
RESOURCE_NAME_HINTS = ("string", "manifest", "config", "index", "route", "url", "host", "server", "domain", "web", "app")
JAVA_NAME_HINTS = ("webview", "config", "buildvars", "url", "server", "domain", "proxy", "launch", "login", "api", "network")
URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>\\]{4,500}")
DOMAIN_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w.-])")
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
