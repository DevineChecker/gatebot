import os,re,time,ssl,socket,random,threading,requests,telebot
from urllib.parse import urlparse, quote_plus
from bs4 import BeautifulSoup
from telebot import apihelper
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from datetime import date

BOT_TOKEN = "8592451831:AAEvVo3CV7FTdkcksE_FNrzGdMTmxV_1m8M"
ADMIN_IDS = [1614278744]
VIP_IDS = [1614278744]
USER_IDS_FILE = 'user_ids.txt'
REGISTERED_FILE = "registered_chats.txt"
GENERATED_CODES_FILE = "generated_codes.txt"
PREMIUM_KEYS_FILE = "premium_keys.txt"
PREMIUM_USERS_FILE = "premium_users.txt"
APPROVED_USERS_FILE = "approved_users.txt"
SEEN_CHATS_FILE = "seen_chats.txt"
BOOST_KEYS_FILE = "boost_keys.txt"
BOOST_REDEEMED_FILE = "boost_redeemed.txt"
DAILY_EXTRA_FILE = "daily_extra.txt"
DAILY_USAGE_FILE = "daily_usage.txt"
PLAN_STICKER_FILE_ID = None  # Add your sticker file ID here

for f in (REGISTERED_FILE, GENERATED_CODES_FILE, PREMIUM_KEYS_FILE, PREMIUM_USERS_FILE, APPROVED_USERS_FILE, SEEN_CHATS_FILE, BOOST_KEYS_FILE, BOOST_REDEEMED_FILE, DAILY_EXTRA_FILE, DAILY_USAGE_FILE):
    if not os.path.exists(f):
        open(f, "a").close()

FREE_DAILY_LIMIT = 900000
PREMIUM_DAILY_LIMIT = 200999
MAX_THREADS_FREE = 89999        
MAX_THREADS_PREMIUM = 222222   

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  
        r'localhost|'  
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  
        r'(?::\d+)?'  
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

GATEWAY_KEYWORDS = [
    "paypal","Stripe","braintree","square","cybersource","authorize.net","adyen","worldpay","lemon-squeezy",
    "sagepay","checkout.com","paddle","mollie","razorpay","paytm","shopify","woocommerce","payeer","payu","skrill",
    "global payments","moneris","bigcommerce","magento","venmo","revolut","eway","upi","apple.com","payflow","payeezy",
    "payoneer","recurly","klarna","paysafe","paysafecard","affirm","afterpay","dwolla","nmi","paytrace","alipay",
    "bitpay","coinbase","amazonpay","2checkout","gocardless","paylike","nexi","zip","sezzle","splitit","quadpay",
    "paystack","flutterwave","skrill","paysera","mercadopago","pagseguro","payu latam","wepay","midtrans","tpv",
    "tpay","payu india","paytabs","myfatoorah","tap","payfort","hyperpay"
]

GATEWAY_PATTERNS = {
    "paypal": [r"paypal\.com", r"paypalobjects\.com", r"paypal(-checkout)?", r"paypal-sdk"],
    "stripe": [r"js\.stripe\.com", r"api\.stripe\.com", r"checkout\.stripe\.com", r"Stripe\("],
    "braintree": [r"braintreegateway\.com", r"braintree\."],
    "square": [r"squareup\.com", r"square\.com\/payments", r"sq-"],
    "adyen": [r"adyen\.com", r"checkoutshopper(-live)?\.adyen\.com", r"AdyenCheckout"],
    "authorize.net": [r"authorize\.net", r"secure\.authorize\.net"],
    "worldpay": [r"worldpay\.com", r"secure\.worldpay"],
    "paddle": [r"paddle\.com", r"paddlecdn"],
    "paypal_payments": [r"paypal-payments", r"paypal-payments\.com"],
    "klarna": [r"klarna\.com", r"klarna-payments"],
    "razorpay": [r"razorpay\.com", r"rzp_"],
    "shopify": [r"cdn\.shopify\.com", r"shopify\.js", r"shopify-payments"],
    "woocommerce": [r"wp-content\/plugins\/woocommerce", r"woocommerce-payments", r"wc-payments"],
    "magento": [r"magento\/", r"static\/version", r"mage-"],
    "bigcommerce": [r"bigcommerce", r"cdn\.bigcommerce"],
    "mercadopago": [r"mercadopago"],
    "payu": [r"payu", r"payu\."],
    "paystack": [r"paystack"],
    "flutterwave": [r"flutterwave"],
    "payoneer": [r"payoneer"],
    "coinbase": [r"coinbase", r"coinbasecommerce"],
    "bitpay": [r"bitpay"],
    "amazonpay": [r"amazonpay"],
    "2checkout": [r"2checkout", r"2checkout\.com"]
}

CMS_PATTERNS = {
    'Shopify': r'cdn\.shopify\.com|shopify\.js|myshopify\.com',
    'WooCommerce': r'wp-content/plugins/woocommerce|woocommerce-payments|wc-payments',
    'WordPress': r'wp-content|wp-includes|wp-admin',
    'Magento': r'magento|static/version|mage-',
    'PrestaShop': r'prestashop',
    'BigCommerce': r'bigcommerce|cdn\.bigcommerce',
    'OpenCart': r'opencart',
    'Drupal': r'drupal',
    'Squarespace': r'squarespace',
    'Wix': r'wix(?:\.com|sdk)'
}

CARD_PATTERNS = {
    'Visa': r'visa[^a-z]|cc-visa|vi-?card',
    'Mastercard': r'master[ -]?card',
    'Amex': r'amex|american.?express',
    'Discover': r'discover'
}

def find_payment_gateways_fast(text):
    if not text:
        return ["Unknown"]
    text_l = text.lower()
    found = []
    
    for kw in GATEWAY_KEYWORDS:
        if kw in text_l and kw not in found:
            found.append(kw)
    
    for name, patterns in GATEWAY_PATTERNS.items():
        for pat in patterns:
            try:
                if re.search(pat, text, flags=re.I):
                    if name not in found:
                        found.append(name)
                    break
            except re.error:
                continue
    return found if found else ["Unknown"]

def find_captcha_details(text):
    if not text:
        return ["No CAPTCHA detected"]
    detected = []
    if re.search(r'recaptcha', text, flags=re.I):
        detected.append("reCAPTCHA")
    if re.search(r'hcaptcha', text, flags=re.I):
        detected.append("hCaptcha")
    if re.search(r'funcaptcha|arkoselabs', text, flags=re.I):
        detected.append("FunCaptcha/Arkose")
    if re.search(r'cloudflare.?turnstile', text, flags=re.I):
        detected.append("Cloudflare Turnstile")
    return detected if detected else ["No CAPTCHA detected"]

def find_cloudflare_services(text):
    if not text:
        return ["No Cloudflare detected"]
    detected = []
    if re.search(r'cloudflare|cdnjs\.cloudflare\.com|challenges\.cloudflare\.com', text, flags=re.I):
        detected.append("Cloudflare (possible)")
    if re.search(r'turnstile', text, flags=re.I):
        detected.append("Cloudflare Turnstile")
    return detected if detected else ["No Cloudflare detected"]

def detect_cms(content):
    if not content:
        return ["None"]
    found = []
    for name, pat in CMS_PATTERNS.items():
        if re.search(pat, content, flags=re.I):
            found.append(name)
    return found if found else ["None"]

def detect_payment_cards(content):
    if not content:
        return ["None"]
    found = []
    for name, pat in CARD_PATTERNS.items():
        if re.search(pat, content, flags=re.I):
            found.append(name)
    return found if found else ["None"]

def check_captcha(response_text):
    if not response_text:
        return False
    captcha_keywords = ['captcha', 'robot', 'verification', 'prove you are not a robot', 'challenge', 'verify']
    return any(keyword in response_text.lower() for keyword in captcha_keywords)

def check_cloudflare(headers, response_text):
    try:
        if headers and "server" in headers and headers["server"] and "cloudflare" in headers["server"].lower():
            return True
    except Exception:
        pass
    cloudflare_indicators = ["please wait", "checking your browser", "cf-ray", "cf-request-id", "cloudflare"]
    if response_text:
        return any(indicator in response_text.lower() for indicator in cloudflare_indicators)
    return False

def check_3d_secure(response_text):
    if not response_text:
        return False
    secure_keywords = [
        "3dsecure", "3d secure", "secure3d", "secure checkout", "verified by visa",
        "mastercard securecode", "secure verification", "3d-authentication", "3d-auth"
    ]
    return any(keyword in response_text.lower() for keyword in secure_keywords)

def check_otp_required(response_text):
    if not response_text:
        return False
    otp_keywords = [
        "otp", "one-time password", "verification code", "enter the code",
        "authentication code", "sms code", "mobile verification"
    ]
    return any(keyword in response_text.lower() for keyword in otp_keywords)

def check_payment_info(response_text):
    if not response_text:
        return "No CVV or CVC Requirement Detected"
    response_text = response_text.lower()
    cvv_required = "cvv" in response_text
    cvc_required = "cvc" in response_text
    if cvv_required and cvc_required:
        return "Both CVV and CVC Required"
    elif cvv_required:
        return "CVV Required"
    elif cvc_required:
        return "CVC Required"
    else:
        return "No CVV or CVC Requirement Detected"

def check_inbuilt_payment_system(response_text, inbuilt_keywords=None):
    if not response_text:
        return False
    if inbuilt_keywords is None:
        inbuilt_keywords = [
            "native payment", "integrated payment", "built-in checkout",
            "secure payment on this site", "on-site payment",
            "internal payment gateway"
        ]
    response_text = response_text.lower()
    pattern = r'\b(?:' + '|'.join(map(re.escape, inbuilt_keywords)) + r')\b'
    return bool(re.search(pattern, response_text))

def check_ssl(hostname, timeout=4):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = {}
                subject = {}
                for t in cert.get('issuer', ()):
                    if len(t) and len(t[0]) >= 2:
                        issuer[t[0][0]] = t[0][1]
                for t in cert.get('subject', ()):
                    if len(t) and len(t[0]) >= 2:
                        subject[t[0][0]] = t[0][1]
                return {'issuer': issuer, 'subject': subject, 'valid_from': cert.get('notBefore'), 'valid_to': cert.get('notAfter')}
    except Exception:
        return None

def fetch_url_content(url, timeout=10):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; MagnetoBot/1.0)'}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r.status_code, r.text, r.headers
    except Exception:
        return None, None, {}

def duckduckgo_search_raw(query, max_results=50):
    results = []
    try:
        q = query.replace('"', '%22')
        q = quote_plus(q, safe='%22')
        url = f"https://html.duckduckgo.com/html/?q={q}"
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; MagnetoBot/1.0)'}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            return results
        soup = BeautifulSoup(r.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href.startswith('http') and href not in results:
                results.append(href)
            if len(results) >= max_results:
                break
    except Exception:
        pass
    return results

def animate_loading(chat_id, stop_event, text="𝐏𝐫𝐨𝐜𝐞𝐬𝐬𝐢𝐧𝐠 𝐏𝐥𝐞𝐚𝐬𝐞 𝐖𝐚𝐢𝐭"):
    emojis = ["⏳", "🔍", "⚙️", "🎲"]
    try:
        sent = bot.send_message(chat_id, f"{emojis[0]} {text}...")
        i = 0
        while not stop_event.is_set():
            i = (i + 1) % len(emojis)
            try:
                bot.edit_message_text(f"{emojis[i]} {text}...", chat_id, sent.message_id)
            except Exception:
                pass
            time.sleep(1)
        try:
            bot.delete_message(chat_id, sent.message_id)
        except Exception:
            pass
    except Exception:
        return

def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip()]

def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as fh:
        if lines:
            fh.write("\n".join(lines) + "\n")
        else:
            fh.write("")

def append_line(path, line):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(str(line) + "\n")

def read_daily_usage():
    data = {}
    if not os.path.exists(DAILY_USAGE_FILE):
        return data
    with open(DAILY_USAGE_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            parts = line.split("|")
            if len(parts) != 3: continue
            uid, dstr, cnt = parts
            try:
                data[uid] = (dstr, int(cnt))
            except:
                continue
    return data

def write_daily_usage(data):
    with open(DAILY_USAGE_FILE, "w", encoding="utf-8") as fh:
        for uid, (dstr, cnt) in data.items():
            fh.write(f"{uid}|{dstr}|{cnt}\n")

def get_today_count(uid):
    data = read_daily_usage()
    u = str(uid)
    today = date.today().isoformat()
    if u in data:
        dstr, cnt = data[u]
        if dstr == today:
            return cnt
        else:
            data[u] = (today, 0)
            write_daily_usage(data)
            return 0
    else:
        data[u] = (today, 0)
        write_daily_usage(data)
        return 0

def add_today_count(uid, add):
    data = read_daily_usage()
    u = str(uid)
    today = date.today().isoformat()
    if u in data:
        dstr, cnt = data[u]
        if dstr == today:
            data[u] = (dstr, cnt + add)
        else:
            data[u] = (today, add)
    else:
        data[u] = (today, add)
    write_daily_usage(data)

def read_daily_extra():
    data = {}
    if not os.path.exists(DAILY_EXTRA_FILE):
        return data
    with open(DAILY_EXTRA_FILE, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            parts = line.split("|")
            if len(parts) != 2: continue
            uid, amt = parts
            try:
                data[uid] = int(amt)
            except:
                continue
    return data

def write_daily_extra(data):
    with open(DAILY_EXTRA_FILE, "w", encoding="utf-8") as fh:
        for uid, amt in data.items():
            fh.write(f"{uid}|{amt}\n")

def get_extra(uid):
    data = read_daily_extra()
    return data.get(str(uid), 0)

def add_extra(uid, amount):
    data = read_daily_extra()
    u = str(uid)
    data[u] = data.get(u, 0) + int(amount)
    write_daily_extra(data)

def consume_extra(uid, amount):
    data = read_daily_extra()
    u = str(uid)
    avail = data.get(u, 0)
    if avail >= amount:
        data[u] = avail - amount
        write_daily_extra(data)
        return 0
    else:
        if avail > 0:
            amount_remaining = amount - avail
            data[u] = 0
            write_daily_extra(data)
            return amount_remaining
        else:
            return amount

def maybe_notify_admins_quota(uid):
    try:
        used = get_today_count(uid)
        base_limit = PREMIUM_DAILY_LIMIT if is_premium(uid) else FREE_DAILY_LIMIT
        extra = get_extra(uid)
        total_allowed = base_limit + extra
        if total_allowed == 0:
            return
        percent = used / total_allowed if total_allowed else 0
        if 0.9 <= percent < 1.0:
            for admin in ADMIN_IDS:
                try:
                    bot.send_message(admin, f"⚠️ Alert: user `{uid}` reached {round(percent*100)}% of daily quota ({used}/{total_allowed}).")
                except:
                    pass
        elif percent >= 1.0:
            for admin in ADMIN_IDS:
                try:
                    bot.send_message(admin, f"❌ User `{uid}` consumed daily quota ({used}/{total_allowed}).")
                except:
                    pass
    except Exception:
        pass

def is_premium(uid):
    return False

def check_and_consume_quota(uid, cost=1):
    uid_s = str(uid)
    base_limit = PREMIUM_DAILY_LIMIT if is_premium(uid) else FREE_DAILY_LIMIT
    extra = get_extra(uid)
    used = get_today_count(uid)
    total_allowed = base_limit + extra

    if used + cost > total_allowed:
        return False

    remaining_cost = consume_extra(uid, cost)
    if remaining_cost > 0:
        add_today_count(uid, remaining_cost)

    maybe_notify_admins_quota(uid)
    return True

def main_menu_markup():
    markup = InlineKeyboardMarkup()
    markup.row(
        InlineKeyboardButton('𝘊𝘰𝘮𝘮𝘢𝘯𝘥𝘴', callback_data='cmd'),
        InlineKeyboardButton('𝘊𝘩𝘢𝘯𝘯𝘦𝘭', url='https://t.me/YUVRAJSINGHX'),
    )
    return markup

bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None)  

def check_token_ok():
    try:
        bot.get_me()
        return True
    except Exception as e:
        print("Token check failed:", e)
        return False

if not check_token_ok():
    print("ERROR: Bot token invalid or network problem. Make sure BOT_TOKEN is correct.")
else:
    print("Bot token OK. Starting...")
    print("Gate Bot starting (patterns-enhanced)...")

@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    data = call.data
    chat_id = call.message.chat.id
    msg_id = call.message.message_id
    user_first = call.from_user.first_name or "User"

    if data == 'cmd':
        text = (
            "*𝗔𝘃𝗮𝗶𝗹𝗮𝗯𝗹𝗲 𝗰𝗼𝗺𝗺𝗮𝗻𝗱𝘀*\n"
            "/register - Register your chat\n"
            "/info - Show profile & plan\n"
            "/gate <domain> - Scan single site\n"
            "/get <domain> - Alias for /gate\n"
            "/mgate - Multi-target scan\n"
            "/checkfile - Upload TXT list to scan\n"
        )
        mk = InlineKeyboardMarkup()
        mk.add(InlineKeyboardButton("Bᴀᴄᴋ", callback_data='back'))
        try:
            bot.edit_message_text(chat_id=chat_id, message_id=msg_id, text=text, reply_markup=mk, parse_mode='Markdown')
        except Exception:
            pass
        bot.answer_callback_query(call.id)
    elif data == 'back':
        try:
            bot.edit_message_text(chat_id=chat_id, message_id=msg_id,
                                  text=f"•════╗\n║ 👑 𝐖𝐞𝐥𝐜𝐨𝐦𝐞\n║ 🌟 ℋ𝒾 {user_first}\n║ ⚡️ Use buttons or commands\n╚═══════════════",
                                  reply_markup=main_menu_markup())
        except Exception:
            pass
        bot.answer_callback_query(call.id)

def make_report_template(url_or_domain, gateways, checkout, captcha, cloud, cms, cards, graphql, ssl_valid, ssl_issuer, ssl_subject, cvv_cvc_status, inbuilt_status, status_code, elapsed_seconds, checked_by):
    report = (
        "┏━━━━『 Gᴀᴛᴇᴡᴀʏ Rᴇsᴜʟᴛs 』━━━━┓\n\n"
        f"🔗 𝗨𝗥𝗟: {url_or_domain}\n"
        f"💳 𝗚𝗮𝘁𝗲𝘄𝗮𝘆𝘀: {gateways}\n"
        f"🛒 𝗖𝗵𝗲𝗰𝗞𝗢𝘂𝗧: {checkout}\n\n"
        "🛡️𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆:\n"
        f"   ├─ 𝗖𝗮𝗽𝘁𝗰𝗵𝗮: {'✅' if 'No CAPTCHA detected' not in captcha else '❌'}\n"
        f"   ├─ 𝗖𝗹𝗼𝘂𝗱𝗳𝗹𝗮𝗿𝗲: {'✅' if 'No Cloudflare detected' not in cloud else '❌'}\n"
        f"   ├─ 𝗣𝗮𝘆𝗺𝗲𝗻𝘁 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆: {('Both 3D Secure and OTP Required' if (check_3d_secure('') and check_otp_required('')) else ('3D Secure' if check_3d_secure('') else ('OTP Required' if check_otp_required('') else '2D (No extra security)')) )}\n"
        f"   └─ 𝗚𝗿𝗮𝗽𝗵𝗤𝗟: {graphql}\n\n"
        "🔐 𝗗𝗲𝘁𝗮𝗶𝗹𝘀:\n"
        f"   ├─ 𝗩𝗮𝗹𝗶𝗱: {ssl_valid}\n"
        f"   ├─ 𝗜𝘀𝘀𝘂𝗲𝗿: {ssl_issuer}\n"
        f"   ├─ 𝗦𝘂𝗯𝗷𝗲𝗰𝘁 𝗖𝗡: {ssl_subject}\n"
        f"   ├─ 𝗖𝗩𝗩/𝗖𝗩𝗖 : {cvv_cvc_status}\n"
        f"   └─ 𝗣𝗮𝘆𝗺𝗲𝗻𝘁 𝗦𝘆𝘀𝘁𝗲𝗺: {inbuilt_status}\n\n"
        "🛍️ 𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺:\n"
        f"   ├─ 𝗖𝗠𝗦: {cms}\n"
        f"   └─ 𝗖𝗮𝗿𝗱𝘀: {cards}\n\n"
        f"💎 𝗦𝘁𝗮𝘁𝘂𝘀 𝗖𝗼𝗱𝗲: {status_code}\n\n"
        f"⏱️ 𝗧𝗶𝗺𝗲: {elapsed_seconds}s\n"
        f"👤 𝗖𝗵𝗲𝗰𝗸𝗲𝗱 𝗯𝘆: {checked_by}\n\n"
        "┗━━━━『 --------------- 』━━━━━┛"
    )
    return report

@bot.message_handler(commands=['gate','get'])
def cmd_gate(m):
    chat = m.chat.id
    parts = m.text.split(' ', 1)
    if len(parts) < 2:
        bot.send_message(chat, "Usage: /gate <domain> (e.g. example.com)")
        return
    raw = parts[1].strip()
    url = raw if re.match(r'^(?:http|https)://', raw, flags=re.I) else 'http://' + raw
    try:
        domain = urlparse(url).hostname
    except Exception:
        bot.send_message(chat, "⚠ Please provide a valid domain.")
        return

    registered = read_lines(REGISTERED_FILE)
    if str(chat) not in registered:
        bot.send_message(chat, "⚠ You must register first using /register")
        return

    if not check_and_consume_quota(m.from_user.id, cost=1):
        base_limit = PREMIUM_DAILY_LIMIT if is_premium(m.from_user.id) else FREE_DAILY_LIMIT
        extra = get_extra(m.from_user.id)
        bot.send_message(chat, f"❌ Not enough daily quota. Used {get_today_count(m.from_user.id)}/{base_limit+extra} today.")
        return

    plan = "Premium" if is_premium(m.from_user.id) else "Free"
    waiting_card_msg = None
    try:
        if PLAN_STICKER_FILE_ID is not None:
            try:
                bot.send_sticker(chat, PLAN_STICKER_FILE_ID)
            except Exception:
                pass
            waiting_card_msg = bot.send_message(chat, f"🔍 𝐒𝐜𝐚𝐧𝐧𝐢𝐧𝐠 𝐏𝐥𝐞𝐚𝐬𝐞 𝐖𝐚𝐢𝐭 `{domain}` (Plan: {plan}) ...")
        else:
            waiting_card_msg = bot.send_message(chat, f"🔍 𝐒𝐜𝐚𝐧𝐧𝐢𝐧𝐠 𝐏𝐥𝐞𝐚𝐬𝐞 𝐖𝐚𝐢𝐭 `{domain}` (Plan: {plan}) ...")

        stop_event = threading.Event()
        t = threading.Thread(target=animate_loading, args=(chat, stop_event, "Checking"))
        t.start()

        start = time.time()
        status, content, headers = fetch_url_content(url, timeout=12)
        elapsed = round(time.time() - start, 2)

        stop_event.set()
        t.join()

        if content is None:
            bot.send_message(chat, "⚠ Failed to fetch the website.")
            try: bot.delete_message(chat, waiting_card_msg.message_id)
            except: pass
            return

        gateways = ", ".join(find_payment_gateways_fast(content))
        captcha = ", ".join(find_captcha_details(content))
        cloud = ", ".join(find_cloudflare_services(content))
        checkout = ", ".join([x for x in [
            "Checkout Page Detected" if re.search(r'checkout', content, flags=re.I) else None,
            "Cart Page Detected" if re.search(r'cart', content, flags=re.I) else None,
            "Payment Page Detected" if re.search(r'payment', content, flags=re.I) else None
        ] if x]) or "No checkout details detected"
        cms = ", ".join(detect_cms(content))
        cards = ", ".join(detect_payment_cards(content))
        graphql = '✅' if re.search(r'graphql|__schema', content, flags=re.I) else '❌'
        ssl_info = check_ssl(domain)
        ssl_issuer = ssl_info['issuer'].get('O') if ssl_info and ssl_info.get('issuer') and ssl_info['issuer'].get('O') else (ssl_info['issuer'].get('CN') if ssl_info and ssl_info.get('issuer') and ssl_info['issuer'].get('CN') else 'Unknown') if ssl_info else 'Invalid SSL'
        ssl_subject = ssl_info['subject'].get('CN') if ssl_info and ssl_info.get('subject') and ssl_info['subject'].get('CN') else 'Unknown' if ssl_info else 'Invalid SSL'
        ssl_valid = '✅' if ssl_info else '❌'
        is_3d = check_3d_secure(content)
        is_otp = check_otp_required(content)
        payment_security_type = (
            "Both 3D Secure and OTP Required" if is_3d and is_otp else
            "3D Secure" if is_3d else
            "OTP Required" if is_otp else
            "2D (No extra security)"
        )
        if check_captcha(content):
            payment_security_type += " | Captcha Detected"
        if check_cloudflare(headers or {}, content):
            payment_security_type += " | Protected by Cloudflare"
        cvv_cvc_status = check_payment_info(content)
        inbuilt_status = "Yes" if check_inbuilt_payment_system(content) else "No"
        checked_by = f"[Req](tg://user?id={m.from_user.id})"

        report = make_report_template(url, gateways, checkout, captcha, cloud, cms, cards, graphql, ssl_valid, ssl_issuer, ssl_subject, cvv_cvc_status, inbuilt_status, status, elapsed, checked_by)

        try:            
            bot.send_message(chat, report, parse_mode='Markdown')
        except Exception as e:
            fname = f"report_{int(time.time())}.txt"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(report)
            with open(fname, "rb") as fh:
                bot.send_document(chat, fh, caption="📄 Report (raw)")
            try: os.remove(fname)
            except: pass

        try: bot.delete_message(chat, waiting_card_msg.message_id)
        except: pass

    except Exception as e:
        try: bot.delete_message(chat, waiting_card_msg.message_id)
        except: pass
        bot.send_message(chat, f"❌ Error while scanning: {e}")

@bot.message_handler(commands=['mgate'])
def cmd_mgate(m):
    chat = m.chat.id
    text = m.text
    lines = text.splitlines()
    if lines and lines[0].strip().startswith('/mgate'):
        lines[0] = lines[0][len('/mgate'):].strip()
    targets = []
    for line in lines:
        for match in re.findall(r'(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line):
            if match.startswith('http'):
                host = urlparse(match).netloc
            else:
                host = match
            if host and host not in targets:
                targets.append(host)
    if not targets:
        bot.send_message(chat, "⚠ No valid targets found. Send domains or URLs.")
        return
    MAX = 1000
    if len(targets) > MAX:
        targets = targets[:MAX]
        bot.send_message(chat, f"⚠ Processing first {MAX} targets only.")

    registered = read_lines(REGISTERED_FILE)
    if str(chat) not in registered:
        bot.send_message(chat, "⚠ You must register first using /register")
        return

    total_cost = len(targets)
    if not check_and_consume_quota(m.from_user.id, cost=total_cost):
        base_limit = PREMIUM_DAILY_LIMIT if is_premium(m.from_user.id) else FREE_DAILY_LIMIT
        extra = get_extra(m.from_user.id)
        bot.send_message(chat, f"❌ Not enough daily quota to scan {len(targets)} targets. Used {get_today_count(m.from_user.id)}/{base_limit+extra} today.")
        return

    for host in targets:
        plan = "Premium" if is_premium(m.from_user.id) else "Free"
        try:
            wait_card = bot.send_message(chat, f"🔍 Scanning {host} (Plan: {plan}) ...")
        except Exception:
            wait_card = bot.send_message(chat, f"🔍 Scanning {host} ...")

        stop_event = threading.Event()
        t = threading.Thread(target=animate_loading, args=(chat, stop_event, "Checking"))
        t.start()
        start = time.time()
        status, content, headers = fetch_url_content("http://" + host)
        elapsed = round(time.time() - start, 2)
        stop_event.set()
        t.join()

        if content is None:
            try: bot.delete_message(chat, wait_card.message_id)
            except: pass
            bot.send_message(chat, f"⚠ Failed to fetch {host}")
            continue

        gateways = ", ".join(find_payment_gateways_fast(content))
        captcha = ", ".join(find_captcha_details(content))
        cloud = ", ".join(find_cloudflare_services(content))
        checkout = ", ".join([x for x in [
            "Checkout Page Detected" if re.search(r'checkout', content, flags=re.I) else None,
            "Cart Page Detected" if re.search(r'cart', content, flags=re.I) else None,
            "Payment Page Detected" if re.search(r'payment', content, flags=re.I) else None
        ] if x]) or "No checkout details detected"
        cms = ", ".join(detect_cms(content))
        cards = ", ".join(detect_payment_cards(content))
        graphql = '✅' if re.search(r'graphql|__schema', content, flags=re.I) else '❌'
        
        ssl_valid = '✅' if headers and ('Strict-Transport-Security' in headers or 'https' in headers.get('Location','').lower() or "https://" in urlparse("http://"+host).scheme) else '❌'
        ssl_issuer = 'Unknown'
        ssl_subject = 'Unknown'
        cvv_cvc_status = check_payment_info(content)
        inbuilt_status = "Yes" if check_inbuilt_payment_system(content) else "No"
        checked_by = f"[Req](tg://user?id={m.from_user.id})"

        report = make_report_template(host, gateways, checkout, captcha, cloud, cms, cards, graphql, ssl_valid, ssl_issuer, ssl_subject, cvv_cvc_status, inbuilt_status, status, elapsed, checked_by)

        try:
            bot.send_message(chat, report, parse_mode='Markdown')
        except Exception:
            fname = f"report_{host}_{int(time.time())}.txt"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(report)
            with open(fname, "rb") as fh:
                bot.send_document(chat, fh, caption=f"📄 Report - {host}")
            try: os.remove(fname)
            except: pass

        try: bot.delete_message(chat, wait_card.message_id)
        except: pass
        time.sleep(0.6)

def scan_target(session, raw, uid):
    try:
        url = raw if re.match(r'^(?:http|https)://', raw, flags=re.I) else "http://" + raw
        host = urlparse(url).hostname or raw
        status, content, headers = None, None, {}
        try:
            r = session.get(url, timeout=6, allow_redirects=True)
            status = r.status_code
            content = r.text
            headers = r.headers
        except Exception:
            if url.startswith("http://"):
                try:
                    r = session.get("https://" + raw, timeout=6, allow_redirects=True)
                    status = r.status_code
                    content = r.text
                    headers = r.headers
                except Exception:
                    pass

        if content is None:
            return f"--- {host} ---\nFailed to fetch.\n\n"

        gateways = ", ".join(find_payment_gateways_fast(content))
        captcha = ", ".join(find_captcha_details(content))
        cloud = ", ".join(find_cloudflare_services(content))
        checkout = ", ".join([x for x in [
            "Checkout" if re.search(r'checkout', content, flags=re.I) else None,
            "Cart" if re.search(r'cart', content, flags=re.I) else None,
            "Payment" if re.search(r'payment', content, flags=re.I) else None
        ] if x]) or "No checkout details detected"
        cms = ", ".join(detect_cms(content))
        cards = ", ".join(detect_payment_cards(content))
        ssl_hint = '✅' if (headers and (headers.get('Strict-Transport-Security') or r.url.startswith('https'))) else '❌'
        ssl_issuer = headers.get('Server', 'Unknown') if headers else 'Unknown'
        ssl_subject = 'Unknown'
        block = (
            f"┏━━━━『 Gᴀᴛᴇᴡᴀʏ Rᴇsᴜʟᴛs 』━━━━┓\n"
            f"🔗 𝗨𝗥𝗟: {host}\n"
            f"💳 𝗚𝗮𝘁𝗲𝘄𝗮𝘆𝘀: {gateways}\n"
            f"🛒 𝗖𝗵𝗲𝗰𝗞𝗢𝘂𝗧: {checkout}\n\n"
            f"🛡️𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆:\n"
            f"   ├─ 𝗖𝗮𝗽𝘁𝗰𝗵𝗮: {'✅' if 'No CAPTCHA detected' not in captcha else '❌'}\n"
            f"   ├─ 𝗖𝗹𝗼𝘂𝗱𝗳𝗹𝗮𝗿𝗲: {'✅' if 'No Cloudflare detected' not in cloud else '❌'}\n"
            f"   ├─ 𝗣𝗮𝘆𝗺𝗲𝗻𝘁 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆: {'3D/OTP/2D (fast)'}\n"
            f"   └─ 𝗚𝗿𝗮𝗽𝗵𝗤𝗟: {'✅' if re.search(r'graphql|__schema', content, flags=re.I) else '❌'}\n\n"
            f"🔐 𝗗𝗲𝘁𝗮𝗶𝗹𝘀:\n"
            f"   ├─ 𝗩𝗮𝗹𝗶𝗱: {ssl_hint}\n"
            f"   ├─ 𝗜𝘀𝘀𝘂𝗲𝗿: {ssl_issuer}\n"
            f"   ├─ 𝗦𝘂𝗯𝗷𝗲𝗰𝘁 𝗖𝗡: {ssl_subject}\n"
            f"   ├─ 𝗖𝗩𝗩/𝗖𝗩𝗖 : {check_payment_info(content)}\n"
            f"   └─ 𝗣𝗮𝘆𝗺𝗲𝗻𝘁 𝗦𝘆𝘀𝘁𝗲𝗺: {'Yes' if check_inbuilt_payment_system(content) else 'No'}\n\n"
            f"🛍️ 𝗣𝗹𝗮𝘁𝗳𝗼𝗿𝗺:\n"
            f"   ├─ 𝗖𝗠𝗦: {cms}\n"
            f"   └─ 𝗖𝗮𝗿𝗱𝘀: {cards}\n\n"
            f"💎 𝗦𝘁𝗮𝘁𝘂𝘀 𝗖𝗼𝗱𝗲: {status}\n\n"
            f"⏱️ 𝗧𝗶𝗺𝗲: quick\n"
            "┗━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        )
        return block
    except Exception as e:
        return f"--- {raw} ---\nError scanning: {e}\n\n"

@bot.message_handler(commands=['checkfile'])
def cmd_checkfile(m):
    bot.send_message(m.chat.id, "📎 Upload a TXT file (domain/URL per line).")
    bot.register_next_step_handler(m, receive_file_for_check)

def receive_file_for_check(message):
    chat = message.chat.id
    uid = message.from_user.id

    registered = read_lines(REGISTERED_FILE)
    if str(chat) not in registered:
        bot.send_message(chat, "⚠ You must register first using /register")
        return

    if not message.document:
        bot.send_message(chat, "❌ You did not attach a file. Re-run /checkfile and upload a TXT file.")
        return
    doc = message.document
    if not doc.file_name.lower().endswith(".txt"):
        bot.send_message(chat, "❌ Please upload a .txt file.")
        return

    try:
        file_info = bot.get_file(doc.file_id)
        file_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_info.file_path}"
        resp = requests.get(file_url, timeout=20)
        if resp.status_code != 200:
            bot.send_message(chat, "❌ Failed to download the file from Telegram.")
            return

        tmp_in = f"uploaded_{uid}_{int(time.time())}.txt"
        with open(tmp_in, "wb") as fh: fh.write(resp.content)
        with open(tmp_in, "r", encoding="utf-8", errors="ignore") as fh:
            lines = [l.strip() for l in fh if l.strip()]

        if not lines:
            bot.send_message(chat, "❌ Uploaded file is empty.")
            os.remove(tmp_in)
            return

        total = len(lines)
        current = get_today_count(uid)
        base_limit = PREMIUM_DAILY_LIMIT if is_premium(uid) else FREE_DAILY_LIMIT
        extra = get_extra(uid)
        total_allowed = base_limit + extra
        if current + total > total_allowed:
            bot.send_message(chat,
                             f"❌ Daily limit exceeded. You've used {current}/{total_allowed} today.\n"
                             f"Trying to scan {total} targets would exceed your limit.")
            try: os.remove(tmp_in)
            except: pass
            return

        threads = min(MAX_THREADS_PREMIUM if is_premium(uid) else MAX_THREADS_FREE, max(2, total))
        wait_msg = bot.send_message(chat, f"🔍 Processing {total} targets using {threads} threads...")

        out_name = f"filecheck_{uid}_{int(time.time())}.txt"
        lock = Lock()
        completed = 0

        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; MagnetoBot/1.0)'})

        with open(out_name, "w", encoding="utf-8") as out:
            out.write(f"File-check results for user {uid}\nTotal targets: {total}\n\n")

        with ThreadPoolExecutor(max_workers=threads) as exe:
            futures = [exe.submit(scan_target, session, raw, uid) for raw in lines]
            for fut in as_completed(futures):
                block = fut.result()
                with lock:
                    with open(out_name, "a", encoding="utf-8") as out:
                        out.write(block)
                    completed += 1
                    if completed % 10 == 0 or completed == total:
                        try:
                            bot.edit_message_text(chat_id=chat, message_id=wait_msg.message_id,
                                                  text=f"🔍 Processed: {completed}/{total}")
                        except Exception:
                            pass

        remaining = total
        rem_after_extra = consume_extra(uid, remaining)
        if rem_after_extra > 0:
            add_today_count(uid, rem_after_extra)

        try: bot.delete_message(chat, wait_msg.message_id)
        except: pass

        with open(out_name, "rb") as docf:
            bot.send_document(chat, docf, caption=f"📄 File-check results — {total} targets")

        bot.send_message(chat, f"✅ Done. Your daily usage now: {get_today_count(uid)}/{base_limit+get_extra(uid)}")
    except Exception as e:
        bot.send_message(chat, f"❌ Error during processing: {e}")
    finally:
        try: os.remove(tmp_in)
        except: pass
        try: os.remove(out_name)
        except: pass

DORK_TEMPLATES = [
    'intext:"pay" inurl:checkout site:{tld}',
    'intext:"payment" inurl:cart site:{tld}',
    'intext:"payu" inurl:membership site:{tld}',
    'intext:"checkout" inurl:"/pay" site:{tld}',
]
COMMON_TLDS = ['com','net','org','co','co.uk','io','store','shop']

@bot.message_handler(commands=['gendork'])
def cmd_gendork(m):
    chat = m.chat.id
    parts = m.text.split()
    n = 3
    if len(parts) >= 2:
        try: n = min(10, int(parts[1]))
        except: n = 3
    generated = []
    for i in range(n):
        tpl = random.choice(DORK_TEMPLATES)
        tld = random.choice(COMMON_TLDS)
        dq = tpl.format(tld=tld)
        generated.append(dq)
    bot.send_message(chat, "🔀 Generated dorks:\n" + "\n".join(f"{i+1}. `{d}`" for i,d in enumerate(generated)), parse_mode='Markdown')
    for dq in generated:
        links = duckduckgo_search_raw(dq, max_results=5)
        if not links:
            bot.send_message(chat, f"❌ No results for dork: `{dq}`", parse_mode='Markdown')
            continue
        first = links[0]
        status, content, headers = fetch_url_content(first, timeout=8)
        if content is None:
            bot.send_message(chat, f"⚠ Failed to fetch result {first}")
            continue
        gateways = ", ".join(find_payment_gateways_fast(content))
        captcha = ", ".join(find_captcha_details(content))
        cloud = ", ".join(find_cloudflare_services(content))
        checkout = ", ".join([x for x in [
            "Checkout Page Detected" if re.search(r'checkout', content, flags=re.I) else None,
            "Cart Page Detected" if re.search(r'cart', content, flags=re.I) else None,
            "Payment Page Detected" if re.search(r'payment', content, flags=re.I) else None
        ] if x]) or "No checkout details detected"
        cms = ", ".join(detect_cms(content))
        cards = ", ".join(detect_payment_cards(content))
        graphql = '✅' if re.search(r'graphql|__schema', content, flags=re.I) else '❌'
        ssl_hint = '✅' if (headers and (headers.get('Strict-Transport-Security') or first.startswith('https'))) else '❌'
        cvv_cvc_status = check_payment_info(content)
        inbuilt_status = "Yes" if check_inbuilt_payment_system(content) else "No"
        checked_by = f"[Req](tg://user?id={m.from_user.id})"
        report = make_report_template(first, gateways, checkout, captcha, cloud, cms, cards, graphql, ssl_hint, 'Unknown', 'Unknown', cvv_cvc_status, inbuilt_status, status, round(0.0,2), checked_by)
        try:
            bot.send_message(chat, report, parse_mode='Markdown')
        except Exception:
            fname = f"gendork_report_{int(time.time())}.txt"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(report)
            with open(fname, "rb") as fh:
                bot.send_document(chat, fh, caption=f"📄 Dork report")
            try: os.remove(fname)
            except: pass

@bot.message_handler(commands=['broadcast'])
def cmd_broadcast(m):
    uid = m.from_user.id
    chat = m.chat.id
    if uid not in ADMIN_IDS:
        bot.send_message(chat, "❌ Not authorized.")
        return
    parts = m.text.split(' ', 1)
    if len(parts) != 2:
        bot.send_message(chat, "Usage: /broadcast <message>")
        return
    text = parts[1]
    targets_set = set()
    try: targets_set.update(read_lines(REGISTERED_FILE))
    except: pass
    try: targets_set.update(read_lines(SEEN_CHATS_FILE))
    except: pass
    targets = []
    for t in targets_set:
        try:
            tid = int(str(t).strip())
            if tid > 0:
                targets.append(tid)
        except:
            continue
    if not targets:
        bot.send_message(chat, "⚠ No targets to broadcast (no registered or seen chats).")
        return
    sent = 0
    failed = 0
    for t in targets:
        try:
            bot.send_message(int(t), text)
            sent += 1
            time.sleep(0.06)
        except Exception:
            failed += 1
            continue
    bot.send_message(chat, f"Broadcast completed. Sent to {sent} chats, failed {failed}. Total targets: {len(targets)}")

@bot.message_handler(commands=['stats'])
def cmd_stats(m):
    uid = m.from_user.id
    chat = m.chat.id
    if uid not in ADMIN_IDS:
        bot.send_message(chat, "❌ Not authorized.")
        return
    total = len(read_lines(REGISTERED_FILE))
    bot.send_message(chat, f"📊 Total registered chats: `{total}`")

@bot.message_handler(commands=['start'])
def cmd_start(m):
    chat_id = m.chat.id
    first = m.from_user.first_name or 'User'
    try:
        # 尝试发送消息
        sent = bot.send_message(chat_id, "🪄")
        mid = sent.message_id
        time.sleep(0.6)
        bot.edit_message_text("✨", chat_id, mid)
        time.sleep(0.6)
        bot.edit_message_text("👾", chat_id, mid)
    except Exception as e:
        # 如果发送失败，可能是权限问题
        print(f"Cannot send message to {chat_id}: {e}")
        # 不要尝试再次发送，这会导致循环错误
        return
    
    try:
        bot.send_message(chat_id,
                         f"┏━━━『 Welcome 』━━━┓\n\n👋 Hello, {first}!\n✨ MAGNETO BOT\n\n⚜️ Use buttons or commands\n┗━━━━━━━━━━━━━━┛",
                         reply_markup=main_menu_markup())
    except Exception as e:
        print(f"Cannot send welcome message to {chat_id}: {e}")
    
    try: 
        mark_seen_chat(chat_id)
    except: 
        pass
        
@bot.message_handler(commands=['register'])
def cmd_register(m):
    chat_id = m.chat.id
    registered = read_lines(REGISTERED_FILE)
    if str(chat_id) not in registered:
        append_line(REGISTERED_FILE, chat_id)
        bot.send_message(chat_id, "✅ You are now registered.")
    else:
        bot.send_message(chat_id, "ℹ You are already registered.")
    try: mark_seen_chat(chat_id)
    except: pass

@bot.message_handler(commands=['info'])
def cmd_info(m):
    user = m.from_user
    chat_id = m.chat.id
    plan = "Premium" if is_premium(user.id) else "Free"
    uname = f"@{user.username}" if user.username else user.first_name
    bot.send_message(chat_id, f"┏━━ Profile ━━━┓\n\n👤 {uname}\n💫 Plan: *{plan}*\n\nID: `{user.id}`\n┗━━━━━━━━━━━━━┛", parse_mode='Markdown')

@bot.message_handler(commands=['about'])
def cmd_about(m):
    bot.send_message(m.chat.id, "ℹ MAGNETO BOT - enhanced scanning tool. Use responsibly.")

@bot.message_handler(func=lambda m: True)
def fallback(m):
    try: mark_seen_chat(m.chat.id)
    except: pass
    

if __name__ == "__main__":
    print("Magneto Bot starting main loop...")
    try:
        bot.infinity_polling(timeout=60, long_polling_timeout = 60)
    except KeyboardInterrupt:
        print("Stopping by user.")
    except Exception as e:
        print("Bot crashed:", e)
