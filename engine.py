import os, json, hmac, hashlib, uuid, random, time, base64, re
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests

HEX_KEY_STR = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
HEX_KEY = bytes.fromhex(HEX_KEY_STR)
_AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

APP_ID = 100067
URL_GUEST_REGISTER = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
URL_TOKEN_GRANT    = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
URL_MAJOR_LOGIN    = "https://loginbp.ppmainecoonghj.com/MajorLogin"
URL_MAJOR_REGISTER = "https://loginbp.ppmainecoonghj.com/MajorRegister"
URL_NEWBIE_CHOICE  = "https://loginbp.ppmainecoonghj.com/ChooseNewbieChoice"

REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","JP":"ja","VN":"vi","TH":"th","BD":"bn",
               "PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt","SG":"en","US":"en"}

UAS = [
    "GarenaMSDK/4.0.44(SM-S928B;Android 14;en;ID;)",
    "GarenaMSDK/4.0.42(Xiaomi 14;Android 14;id;ID;)",
    "GarenaMSDK/4.0.43(SM-G998B;Android 13;id;ID;)",
]

def _ua(): return random.choice(UAS)

def encode_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def field(num, val):
    if isinstance(val, dict):
        nested = b''.join(field(k, v) for k, v in val.items())
        return encode_varint((num << 3) | 2) + encode_varint(len(nested)) + nested
    if isinstance(val, int):
        return encode_varint((num << 3) | 0) + encode_varint(val)
    if isinstance(val, str):
        val = val.encode()
    if isinstance(val, bytes):
        return encode_varint((num << 3) | 2) + encode_varint(len(val)) + val
    return b''

def build_proto(fields):
    return b''.join(field(k, v) for k, v in fields.items())

def aes_enc(plain_hex):
    data = bytes.fromhex(plain_hex)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(data, AES.block_size))

def enc_hex(hex_data):
    return aes_enc(hex_data).hex()

def guest_register(password):
    try:
        body = json.dumps({"app_id": APP_ID, "client_type": 2,
                           "password": password, "source": 2}, separators=(',', ':'))
        sig = hmac.new(HEX_KEY, body.encode(), hashlib.sha256).hexdigest()
        r = requests.post(URL_GUEST_REGISTER, data=body, timeout=(3, 8), verify=False, headers={
            "User-Agent": _ua(), "Authorization": "Signature " + sig,
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json", "Host": "100067.connect.garena.com",
        })
        if r.status_code == 200:
            j = r.json()
            return j.get("data", {}).get("uid")
    except Exception:
        pass
    return None

def token_grant(uid, password):
    try:
        body = json.dumps({"client_id": APP_ID, "client_secret": HEX_KEY_STR,
                           "client_type": 2, "device_id": "02-" + str(uuid.uuid4()),
                           "password": password, "response_type": "token", "uid": uid},
                          separators=(',', ':'))
        r = requests.post(URL_TOKEN_GRANT, data=body, timeout=(3, 8), verify=False, headers={
            "User-Agent": _ua(), "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json", "Host": "100067.connect.garena.com",
        })
        if r.status_code == 200:
            j = r.json()
            d = j.get("data", {})
            if "access_token" in d and "open_id" in d:
                return d["access_token"], d["open_id"]
    except Exception:
        pass
    return None

def major_login(access_token, open_id, lang="en"):
    try:
        device_id = f"Google|{uuid.uuid4()}"
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        f = {
            3: now, 4: "free fire", 5: 4, 7: "1.132.1", 8: "2019116753",
            9: "Android OS 13 / API-33", 10: "Handheld", 11: "SM-A525F",
            12: 1280, 13: 720, 14: "240",
            15: "x86-64 SSE3 SSE4.1 SSE4.2 AVX AVX2 | 2400 | 4",
            16: 6000, 17: "Adreno (TM) 640", 18: "OpenGL ES 3.1 v1.46",
            19: device_id, 20: "105.235.139.91", 21: lang,
            22: open_id, 23: "4", 24: "Handheld", 25: "SM-A525F",
            26: "ID", 29: access_token, 30: 1,
            41: "Telkomsel", 42: "WIFI", 92: 20000, 93: "android_max",
            97: 1, 98: 1, 99: "4", 100: "4", 104: 77149, 105: 1,
        }
        payload = bytes.fromhex(enc_hex(build_proto(f).hex()))
        r = requests.post(URL_MAJOR_LOGIN, data=payload, timeout=(3, 8), verify=False, headers={
            "User-Agent": _ua(), "Authorization": "Bearer " + access_token,
            "Content-Type": "application/octet-stream", "X-GA": "v1 1",
            "ReleaseVersion": "OB55", "X-Unity-Version": "2018.4.12f1",
            "Host": "loginbp.ppmainecoonghj.com",
        })
        if r.status_code != 200 or len(r.content) < 20:
            return None
        text = r.content.decode('utf-8', errors='ignore')
        jwt = None
        m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", text)
        if m: jwt = m.group(0)
        acc_id = None
        if jwt:
            try:
                p = jwt.split('.')[1]; p += '=' * (4 - len(p) % 4)
                dec = json.loads(base64.urlsafe_b64decode(p))
                acc_id = dec.get('account_id') or dec.get('external_id')
            except Exception:
                pass
        if not acc_id:
            nums = re.findall(r'\b\d{10,12}\b', text)
            if nums: acc_id = nums[0]
        if acc_id:
            return {"account_id": str(acc_id), "jwt_token": jwt or ""}
    except Exception:
        pass
    return None

def major_register(access_token, open_id, lang="en", nick="XORA"):
    try:
        payload = {1: nick, 2: access_token, 3: open_id, 5: 102000007, 6: 4,
                   7: 1, 13: 1, 15: lang, 16: 1, 17: 1}
        enc = aes_enc(build_proto(payload).hex())
        requests.post(URL_MAJOR_REGISTER, data=enc, timeout=(3, 8), verify=False, headers={
            "User-Agent": _ua(), "Authorization": "Bearer",
            "Content-Type": "application/x-www-form-urlencoded", "X-GA": "v1 1",
            "ReleaseVersion": "OB55", "X-Unity-Version": "2018.4.12f1",
            "Host": "loginbp.ppmainecoonghj.com",
        })
        return major_login(access_token, open_id, lang)
    except Exception:
        return None

def create_account(region="ID"):
    try:
        pw = os.urandom(16).hex()
        uid = guest_register(pw)
        if not uid: return None
        tok = token_grant(uid, pw)
        if not tok: return None
        at, oid = tok
        lang = REGION_LANG.get(region.upper(), "en")
        nick = "XORA" + "".join(random.choices("0123456789", k=4))
        login = major_register(at, oid, lang, nick)
        if not login: return None
        return {
            "uid": str(uid),
            "password": pw,
            "name": nick,
            "account_id": login["account_id"],
            "jwt_token": login.get("jwt_token", ""),
            "region": region.upper(),
            "created_at": datetime.now().isoformat(),
        }
    except Exception:
        return None