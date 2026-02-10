import telebot
from telebot import types
import json
import os
from datetime import datetime, timedelta
import hashlib
import secrets

# ================= BOT CONFIG =================

BOT_TOKEN = "8454713031:AAHwHHrnTr_6LUrYfgTHwziMgsq39HQG4Rw"
ADMIN_ID = 7517279474
ADMIN_USERNAME = "@Socialpaysupport"
BOT_LINK = "https://t.me/socialpaybot"

bot = telebot.TeleBot(BOT_TOKEN)

# ================= FILES =================

USERS_FILE = "users.json"
TASKS_FILE = "tasks.json"
REFERRALS_FILE = "referrals.json"
SUBMISSIONS_FILE = "submissions.json"
WALLETS_FILE = "wallets.json"
BANK_FILE = "bank_details.json"
WITHDRAWALS_FILE = "withdrawals.json"
EXCHANGES_FILE = "exchanges.json"
PIN_FILE = "user_pins.json"
TRANSFER_AUDIT_FILE = "logs/transfer_audit.json"
TRANSFER_LIMITS_FILE = "transfer_limits.json"

# Create logs directory
os.makedirs("logs", exist_ok=True)

# ================= TRANSFER CONFIG =================

MAX_TRANSFERS_PER_DAY = 5
MAX_TRANSFER_AMOUNT = 100000  # ₦100,000
PIN_MAX_ATTEMPTS = 3
PIN_LOCKOUT_MINUTES = 30

# ================= SECURITY FUNCTIONS =================

def hash_pin(pin):
    """Hash PIN with salt for secure storage"""
    salt = secrets.token_hex(16)
    pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000)
    return f"{salt}${pin_hash.hex()}"

def verify_pin(pin, pin_hash):
    """Verify PIN against stored hash"""
    try:
        salt, stored_hash = pin_hash.split('$')
        pin_hash_check = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000)
        return pin_hash_check.hex() == stored_hash
    except:
        return False

def log_transfer_event(event_type, from_user, to_user, amount, status, reason="", admin_id=None):
    """Log all transfer-related events to audit file"""
    audit_logs = load(TRANSFER_AUDIT_FILE)
    
    log_entry = {
        "type": event_type,
        "from": from_user,
        "to": to_user,
        "amount": amount,
        "admin_id": admin_id,
        "time": datetime.now().isoformat(),
        "status": status,
        "reason": reason
    }
    
    log_id = f"log_{int(datetime.now().timestamp())}_{secrets.token_hex(4)}"
    audit_logs[log_id] = log_entry
    save(TRANSFER_AUDIT_FILE, audit_logs)
    return log_id

def check_pin_lockout(user_id):
    """Check if user is locked out due to failed PIN attempts"""
    pins = load(PIN_FILE)
    user_id = str(user_id)
    
    if user_id not in pins:
        return False
    
    lockout_until = pins[user_id].get("lockout_until")
    if not lockout_until:
        return False
    
    lockout_time = datetime.fromisoformat(lockout_until)
    if datetime.now() < lockout_time:
        return True
    
    # Lockout expired, clear it
    pins[user_id]["lockout_until"] = None
    pins[user_id]["failed_attempts"] = 0
    save(PIN_FILE, pins)
    return False

def record_failed_pin(user_id):
    """Record failed PIN attempt and lock if needed"""
    pins = load(PIN_FILE)
    user_id = str(user_id)
    
    if user_id not in pins:
        return
    
    pins[user_id]["failed_attempts"] = pins[user_id].get("failed_attempts", 0) + 1
    
    if pins[user_id]["failed_attempts"] >= PIN_MAX_ATTEMPTS:
        lockout_until = datetime.now() + timedelta(minutes=PIN_LOCKOUT_MINUTES)
        pins[user_id]["lockout_until"] = lockout_until.isoformat()
        pins[user_id]["failed_attempts"] = 0
    
    save(PIN_FILE, pins)

def reset_failed_attempts(user_id):
    """Reset failed PIN attempts after successful entry"""
    pins = load(PIN_FILE)
    user_id = str(user_id)
    
    if user_id in pins:
        pins[user_id]["failed_attempts"] = 0
        pins[user_id]["lockout_until"] = None
        save(PIN_FILE, pins)

def get_today_transfer_count(user_id):
    """Get number of transfers user made today"""
    limits = load(TRANSFER_LIMITS_FILE)
    user_id = str(user_id)
    today = datetime.now().date().isoformat()
    
    if user_id not in limits:
        return 0
    
    if limits[user_id].get("date") != today:
        return 0
    
    return limits[user_id].get("count", 0)

def increment_transfer_count(user_id):
    """Increment user's daily transfer count"""
    limits = load(TRANSFER_LIMITS_FILE)
    user_id = str(user_id)
    today = datetime.now().date().isoformat()
    
    if user_id not in limits or limits[user_id].get("date") != today:
        limits[user_id] = {"date": today, "count": 1}
    else:
        limits[user_id]["count"] += 1
    
    save(TRANSFER_LIMITS_FILE, limits)

def generate_submission_hash(user_id, task_id):
    """Generate unique hash for user-task combination"""
    return hashlib.sha256(f"{user_id}_{task_id}".encode()).hexdigest()

def has_user_submitted_task(user_id, task_id):
    """Check if user has already submitted this specific task"""
    submissions = load(SUBMISSIONS_FILE)
    user_id = str(user_id)
    
    for sub_id, sub_data in submissions.items():
        if (sub_data.get("user_id") == user_id and 
            sub_data.get("task_id") == task_id):
            return True
    return False

def validate_user_id(user_id):
    """Security: Validate user ID format"""
    try:
        user_id = str(user_id)
        if not user_id.isdigit():
            return False
        if len(user_id) > 15:
            return False
        return True
    except:
        return False

def validate_amount(amount):
    """Security: Validate monetary amounts"""
    try:
        amount = float(amount)
        if amount <= 0:
            return False
        if amount > 1000000:
            return False
        return True
    except:
        return False

def validate_pin(pin):
    """Validate PIN format - must be 4 digits"""
    try:
        if len(pin) != 4:
            return False
        int(pin)
        return True
    except:
        return False

def rate_limit_check(user_id, action_type):
    """Security: Basic rate limiting"""
    rate_limits = load("rate_limits.json") if os.path.exists("rate_limits.json") else {}
    user_id = str(user_id)
    current_time = datetime.now().timestamp()
    
    if user_id not in rate_limits:
        rate_limits[user_id] = {}
    
    if action_type not in rate_limits[user_id]:
        rate_limits[user_id][action_type] = []
    
    rate_limits[user_id][action_type] = [
        t for t in rate_limits[user_id][action_type] 
        if current_time - t < 60
    ]
    
    if len(rate_limits[user_id][action_type]) >= 10:
        return False
    
    rate_limits[user_id][action_type].append(current_time)
    save("rate_limits.json", rate_limits)
    return True

# ================= UTIL FUNCTIONS =================

def load(file):
    if not os.path.exists(file):
        return {}
    try:
        with open(file, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save(file, data):
    with open(file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def get_wallet(user_id):
    if not validate_user_id(user_id):
        return None
    
    wallets = load(WALLETS_FILE)
    user_id = str(user_id)
    if user_id not in wallets:
        wallets[user_id] = {
            "naira": 0.0,
            "dollar": 0.0,
            "completed_tasks": 0,
            "pending_tasks": 0,
            "referral_count": 0,
            "referral_naira": 0.0,
            "referral_dollar": 0.0
        }
        save(WALLETS_FILE, wallets)
    return wallets[user_id]

def update_wallet(user_id, key, amount):
    if not validate_user_id(user_id):
        return False
    
    wallets = load(WALLETS_FILE)
    user_id = str(user_id)
    if user_id in wallets:
        wallets[user_id][key] += amount
        if key in ["naira", "dollar", "referral_naira", "referral_dollar"]:
            if wallets[user_id][key] < 0:
                wallets[user_id][key] = 0
        save(WALLETS_FILE, wallets)
        return True
    return False

def delete_message_safe(chat_id, message_id):
    """Safely delete a message"""
    try:
        bot.delete_message(chat_id, message_id)
    except:
        pass

def count_tasks():
    """Count total, completed, and remaining tasks"""
    tasks = load(TASKS_FILE)
    active_tasks = [t for t in tasks.values() if t.get("status") == "active"]
    
    total = len(active_tasks)
    completed = sum(len(t.get("completed_by", [])) for t in active_tasks)
    remaining = total - completed
    
    return total, completed, remaining

def check_and_delete_completed_tasks():
    """Check all tasks and delete those that have reached their user limit"""
    tasks = load(TASKS_FILE)
    tasks_modified = False
    
    for task_id, task_data in list(tasks.items()):
        if task_data.get("status") != "active":
            continue
            
        max_users = task_data.get("max_users", 1)
        completed_by = task_data.get("completed_by", [])
        
        if len(completed_by) >= max_users:
            del tasks[task_id]
            tasks_modified = True
            print(f"✅ Task {task_id} deleted - reached limit of {max_users} unique users")
    
    if tasks_modified:
        save(TASKS_FILE, tasks)

def has_user_completed_similar_task(user_id, platform, task_type, link):
    """Check if user has already completed this exact task or very similar task"""
    tasks = load(TASKS_FILE)
    user_id = str(user_id)
    
    for task_id, task_data in tasks.items():
        if (task_data.get("platform") == platform and 
            task_data.get("task_type") == task_type and
            task_data.get("link") == link and
            user_id in task_data.get("completed_by", [])):
            return True
    
    return False

# ================= USER STATES =================

user_role = {}
user_state = {}
temp_data = {}
admin_state = {}
last_message = {}

# ================= MAIN MENUS =================

def get_role_selection_menu():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("💸 Earner")
    kb.row("📢 Advertiser")
    return kb

def earner_menu(chat_id=None):
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("🎯 Available Tasks")
    kb.row("💰 My Balance", "👥 My Referrals")
    kb.row("💸 Transfer", "💱 Exchange Currency")
    kb.row("💳 Payment Details", "ℹ️ My Information")
    kb.row("💬 Support", "🏡 Home")
    if chat_id == ADMIN_ID:
        kb.row("⚙️ Admin Dashboard")
    return kb

def advertiser_menu():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("💬 Contact Admin")
    kb.row("🏡 Home")
    return kb

def admin_menu():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("➕ Create Task", "🗑️ Delete Task")
    kb.row("✅ Approve/Reject Task")
    kb.row("👤 Manage User", "🔐 PIN Management")
    kb.row("💱 Exchange Requests", "💸 Withdrawal Requests")
    kb.row("✏️ Edit Withdrawal Status", "🔄 Transfer Reversal")
    kb.row("📢 Broadcast", "💬 Message User")
    kb.row("ℹ️ Users Info", "💰 Adjust Balance")
    kb.row("📊 Transfer Logs")
    kb.row("🔙 Back to Main")
    return kb

def back_button():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    return kb

# ================= AUTO DELETE PREVIOUS MESSAGE =================

def send_and_track(chat_id, text, **kwargs):
    """Send message and track it for auto-delete"""
    if chat_id in last_message:
        delete_message_safe(chat_id, last_message[chat_id])
    
    msg = bot.send_message(chat_id, text, **kwargs)
    last_message[chat_id] = msg.message_id
    return msg

def send_photo_and_track(chat_id, photo, **kwargs):
    """Send photo and track it for auto-delete"""
    if chat_id in last_message:
        delete_message_safe(chat_id, last_message[chat_id])
    
    msg = bot.send_photo(chat_id, photo, **kwargs)
    last_message[chat_id] = msg.message_id
    return msg

# ================= HOME BUTTON HANDLER =================

@bot.message_handler(func=lambda m: m.text == "🏡 Home")
def handle_home(m):
    cid = m.chat.id
    
    delete_message_safe(cid, m.message_id)
    
    # Clear all states
    user_state.pop(cid, None)
    temp_data.pop(cid, None)
    admin_state.pop(cid, None)
    user_role.pop(cid, None)
    
    users = load(USERS_FILE)
    user_id = str(cid)
    
    full_name = m.from_user.first_name or "User"
    if m.from_user.last_name:
        full_name += f" {m.from_user.last_name}"
    
    referral_link = f"{BOT_LINK}?start={user_id}"
    
    welcome_msg = (
        f"👋 Welcome back, {full_name}! 🎉\n\n"
        "🤖 **SOCIALPAY** 🤖\n\n"
        "Earn money by completing simple social media tasks! 💰\n\n"
        "invite your friend and earn reward\n\n"
        "after he is completed 10 task using your invitation link\n\n"
        "Please select your role to continue:"
    )
    
    send_and_track(
        cid,
        welcome_msg,
        reply_markup=get_role_selection_menu(),
        parse_mode="Markdown"
    )

# ================= BACK BUTTON HANDLER =================

@bot.message_handler(func=lambda m: m.text == "🔙 Back")
def handle_back(m):
    cid = m.chat.id
    
    delete_message_safe(cid, m.message_id)
    
    user_state.pop(cid, None)
    temp_data.pop(cid, None)
    admin_state.pop(cid, None)
    
    if cid == ADMIN_ID and user_role.get(cid) is None:
        send_and_track(cid, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    elif user_role.get(cid) == "earner":
        send_and_track(cid, "💸 Earner Menu", reply_markup=earner_menu(cid))
    elif user_role.get(cid) == "advertiser":
        send_and_track(cid, "📢 Advertiser Menu", reply_markup=advertiser_menu())
    else:
        send_and_track(cid, "Please select your role:", reply_markup=get_role_selection_menu())

# ================= START COMMAND =================

@bot.message_handler(commands=["start"])
def start(msg):
    if not rate_limit_check(msg.chat.id, "start"):
        return
    
    users = load(USERS_FILE)
    user_id = str(msg.chat.id)
    is_new = user_id not in users

    ref_id = None
    command_parts = msg.text.split()
    if len(command_parts) > 1:
        ref_id = command_parts[1]
        if not validate_user_id(ref_id):
            ref_id = None

    full_name = msg.from_user.first_name or "User"
    if msg.from_user.last_name:
        full_name += f" {msg.from_user.last_name}"
    
    full_name = full_name[:100]

    if is_new:
        users[user_id] = {
            "name": full_name,
            "joined": str(datetime.now()),
            "referrer": ref_id if ref_id and ref_id != user_id else None
        }
        save(USERS_FILE, users)
        get_wallet(user_id)
        
        bot.send_message(
            ADMIN_ID,
            f"🆕 **NEW USER JOINED**\n\n"
            f"👤 Name: {full_name}\n"
            f"🆔 ID: `{msg.chat.id}`",
            parse_mode="Markdown"
        )

        if ref_id and str(ref_id) != str(user_id):
            referrals = load(REFERRALS_FILE)
            if ref_id not in referrals:
                referrals[ref_id] = []
            referrals[ref_id].append({
                "user_id": user_id,
                "name": full_name,
                "tasks_completed": 0,
                "reward_paid": False,
                "joined": str(datetime.now())
            })
            save(REFERRALS_FILE, referrals)

    referral_link = f"{BOT_LINK}?start={user_id}"

    welcome_msg = (
        f"👋 Welcome {full_name}! 🎉\n\n\n"
        "🤖 **SOCIAL PAY** 🤖\n\n"
        "Earn money by completing simple social media tasks! 💰\n\n\n"
        "Invite friends and earn rewards! 🎁\n\n"
        "This Social Pay company operates under a strategic partnership with Mobile Skills Network.\n\n"
        f"🔗 **Your Referral Link:**\n`{referral_link}`\n\n"
        "Invite friends and earn rewards! 🎁 after completed 10 simple task\n\n"
        "🚀 Not sure how to use our service? No worries! 😎\n\n"  
        "Join our **Telegram Groupl** now: 🔗\n\n"
        " https://t.me/Socialearningpay\n\n"
        "For discuss with our customers including earners and Advertisers\n\n\n"
        "Join Our Telegram channel for Waching tutorial video of how to use our services\n\n"
        "https://t.me/socialpaychannel\n\n"
        "🎥 Watch the **tutorial video** on how to use the bot and start earning happily 💰✨!\n\n"
        "📌 Don't miss out – one step away from your earnings! 🎯\n\n\n"
        "are you advertiser or earner\n\n"
        "Please select your role to continue:"
    )

    send_and_track(
        msg.chat.id,
        welcome_msg,
        reply_markup=get_role_selection_menu(),
        parse_mode="Markdown"
    )

# ================= ROLE SELECTION =================

@bot.message_handler(func=lambda m: m.text == "💸 Earner")
def select_earner(m):
    delete_message_safe(m.chat.id, m.message_id)
    user_role[m.chat.id] = "earner"
    send_and_track(
        m.chat.id,
        "💸 Welcome to Earner Mode!\n\nComplete tasks to earn money! 🎯",
        reply_markup=earner_menu(m.chat.id)
    )

@bot.message_handler(func=lambda m: m.text == "📢 Advertiser")
def select_advertiser(m):
    delete_message_safe(m.chat.id, m.message_id)
    user_role[m.chat.id] = "advertiser"
    send_and_track(
        m.chat.id,
        f"📢 Welcome to Advertiser Mode!\n\n"
        f"To advertise with us, please contact our support:\n\n"
        f"👤 Agent: {ADMIN_USERNAME}\n\n"
        f"Click 'Contact Agent' button below to start a conversation.",
        reply_markup=advertiser_menu()
    )

# ================= WALLET TRANSFER SYSTEM =================

@bot.message_handler(func=lambda m: m.text == "💸 Transfer")
def transfer_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    user_id = str(m.chat.id)
    pins = load(PIN_FILE)
    
    # Check if user has PIN
    if user_id not in pins or not pins[user_id].get("pin_hash"):
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("🔐 Create PIN")
        kb.row("🔙 Back")
        
        send_and_track(
            m.chat.id,
            "🔐 **PIN REQUIRED**\n\n"
            "To use the transfer feature, you need to create a 4-digit PIN first.\n\n"
            "This PIN will protect your transfers and keep your money safe.\n\n"
            "Click 'Create PIN' to set up your security PIN now.",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "transfer_need_pin"
        return
    
    # Check if locked out
    if check_pin_lockout(user_id):
        send_and_track(
            m.chat.id,
            f"🔒 **ACCOUNT LOCKED**\n\n"
            f"Too many failed PIN attempts.\n\n"
            f"Please wait {PIN_LOCKOUT_MINUTES} minutes before trying again.",
            reply_markup=back_button(),
            parse_mode="Markdown"
        )
        return
    
    # Check daily limit
    today_count = get_today_transfer_count(user_id)
    if today_count >= MAX_TRANSFERS_PER_DAY:
        send_and_track(
            m.chat.id,
            f"⚠️ **DAILY LIMIT REACHED**\n\n"
            f"You have reached your daily transfer limit of {MAX_TRANSFERS_PER_DAY} transfers.\n\n"
            f"Please try again tomorrow.",
            reply_markup=back_button(),
            parse_mode="Markdown"
        )
        return
    
    wallet = get_wallet(user_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        f"💸 **TRANSFER MONEY**\n\n"
        f"Your Balance: ₦{wallet['naira']:.2f}\n\n"
        f"📊 Transfers Today: {today_count}/{MAX_TRANSFERS_PER_DAY}\n"
        f"💰 Max Amount: ₦{MAX_TRANSFER_AMOUNT:,.0f}\n\n"
        f"Enter the Receiver's User ID:",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    user_state[m.chat.id] = "transfer_enter_receiver"

@bot.message_handler(func=lambda m: m.text == "🔐 Create PIN" and user_state.get(m.chat.id) == "transfer_need_pin")
def create_pin_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        "🔐 **CREATE YOUR PIN**\n\n"
        "Enter a 4-digit PIN (numbers only):\n\n"
        "⚠️ Remember this PIN - you'll need it for all transfers!\n\n"
        "Example: 1234",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    user_state[m.chat.id] = "create_pin_enter"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "create_pin_enter")
def create_pin_save(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "💸 Earner Menu", reply_markup=earner_menu(m.chat.id))
    
    if not validate_pin(m.text):
        send_and_track(
            m.chat.id,
            "❌ Invalid PIN!\n\nPIN must be exactly 4 digits.\n\nTry again:",
            reply_markup=back_button()
        )
        return
    
    user_id = str(m.chat.id)
    pins = load(PIN_FILE)
    
    pins[user_id] = {
        "pin_hash": hash_pin(m.text),
        "created": datetime.now().isoformat(),
        "failed_attempts": 0,
        "lockout_until": None
    }
    save(PIN_FILE, pins)
    
    log_transfer_event("pin_created", user_id, None, 0, "success", "User created PIN")
    
    send_and_track(
        m.chat.id,
        "✅ **PIN CREATED SUCCESSFULLY!**\n\n"
        "Your 4-digit PIN has been set.\n\n"
        "🔐 Keep it safe and never share it with anyone!\n\n"
        "You can now use the transfer feature.",
        reply_markup=earner_menu(m.chat.id),
        parse_mode="Markdown"
    )
    user_state.pop(m.chat.id, None)

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "transfer_enter_receiver")
def transfer_enter_receiver(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "💸 Earner Menu", reply_markup=earner_menu(m.chat.id))
    
    receiver_id = m.text.strip()
    sender_id = str(m.chat.id)
    
    # Validate receiver ID
    if not validate_user_id(receiver_id):
        send_and_track(m.chat.id, "❌ Invalid User ID format!\n\nTry again:", reply_markup=back_button())
        return
    
    # Check if trying to send to self
    if receiver_id == sender_id:
        send_and_track(m.chat.id, "❌ You cannot transfer money to yourself!\n\nEnter a different User ID:", reply_markup=back_button())
        return
    
    # Check if receiver exists
    users = load(USERS_FILE)
    if receiver_id not in users:
        send_and_track(m.chat.id, f"❌ User ID {receiver_id} not found!\n\nCheck the ID and try again:", reply_markup=back_button())
        return
    
    receiver_name = users[receiver_id].get("name", "Unknown")
    
    temp_data[m.chat.id] = {
        "transfer_receiver": receiver_id,
        "receiver_name": receiver_name
    }
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Correct", callback_data="transfer_confirm_receiver"),
        types.InlineKeyboardButton("❌ Wrong ID", callback_data="transfer_wrong_receiver")
    )
    
    msg = bot.send_message(
        m.chat.id,
        f"📋 **CONFIRM RECEIVER**\n\n"
        f"Receiver Name: {receiver_name}\n"
        f"Receiver ID: `{receiver_id}`\n\n"
        f"Is this the correct person?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id

@bot.callback_query_handler(func=lambda c: c.data == "transfer_wrong_receiver")
def transfer_wrong_receiver(c):
    bot.edit_message_text(
        "Please enter the correct User ID:",
        c.message.chat.id,
        c.message.message_id
    )
    user_state[c.message.chat.id] = "transfer_enter_receiver"

@bot.callback_query_handler(func=lambda c: c.data == "transfer_confirm_receiver")
def transfer_confirm_receiver(c):
    bot.delete_message(c.message.chat.id, c.message.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    sender_wallet = get_wallet(c.message.chat.id)
    
    bot.send_message(
        c.message.chat.id,
        f"💰 **ENTER AMOUNT**\n\n"
        f"Your Balance: ₦{sender_wallet['naira']:.2f}\n"
        f"Max Transfer: ₦{MAX_TRANSFER_AMOUNT:,.0f}\n\n"
        f"How much do you want to send?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    user_state[c.message.chat.id] = "transfer_enter_amount"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "transfer_enter_amount")
def transfer_enter_amount(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state[m.chat.id] = "transfer_enter_receiver"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(m.chat.id, "Enter the Receiver's User ID:", reply_markup=kb)
    
    if not validate_amount(m.text):
        send_and_track(m.chat.id, "❌ Invalid amount!\n\nEnter a valid number:", reply_markup=back_button())
        return
    
    try:
        amount = float(m.text)
    except:
        send_and_track(m.chat.id, "❌ Invalid amount!\n\nEnter a number:", reply_markup=back_button())
        return
    
    sender_id = str(m.chat.id)
    sender_wallet = get_wallet(sender_id)
    
    # Check if amount exceeds balance
    if amount > sender_wallet["naira"]:
        send_and_track(
            m.chat.id,
            f"❌ **INSUFFICIENT BALANCE**\n\n"
            f"Amount: ₦{amount:.2f}\n"
            f"Your Balance: ₦{sender_wallet['naira']:.2f}\n\n"
            f"You need ₦{amount - sender_wallet['naira']:.2f} more.\n\n"
            f"Enter a smaller amount:",
            reply_markup=back_button(),
            parse_mode="Markdown"
        )
        return
    
    # Check if amount exceeds max transfer limit
    if amount > MAX_TRANSFER_AMOUNT:
        send_and_track(
            m.chat.id,
            f"❌ **AMOUNT TOO HIGH**\n\n"
            f"Maximum transfer amount: ₦{MAX_TRANSFER_AMOUNT:,.0f}\n\n"
            f"Enter a smaller amount:",
            reply_markup=back_button(),
            parse_mode="Markdown"
        )
        return
    
    temp_data[m.chat.id]["transfer_amount"] = amount
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        f"🔐 **ENTER YOUR PIN**\n\n"
        f"Enter your 4-digit PIN to authorize this transfer:",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    user_state[m.chat.id] = "transfer_enter_pin"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "transfer_enter_pin")
def transfer_enter_pin(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state[m.chat.id] = "transfer_enter_amount"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        sender_wallet = get_wallet(m.chat.id)
        return send_and_track(
            m.chat.id,
            f"💰 **ENTER AMOUNT**\n\nYour Balance: ₦{sender_wallet['naira']:.2f}\n\nHow much do you want to send?",
            reply_markup=kb,
            parse_mode="Markdown"
        )
    
    sender_id = str(m.chat.id)
    
    # Check lockout
    if check_pin_lockout(sender_id):
        send_and_track(
            m.chat.id,
            f"🔒 **ACCOUNT LOCKED**\n\n"
            f"Too many failed PIN attempts.\n\n"
            f"Please wait {PIN_LOCKOUT_MINUTES} minutes.",
            reply_markup=earner_menu(m.chat.id),
            parse_mode="Markdown"
        )
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    # Verify PIN
    pins = load(PIN_FILE)
    if not verify_pin(m.text, pins[sender_id]["pin_hash"]):
        record_failed_pin(sender_id)
        
        pins = load(PIN_FILE)
        remaining = PIN_MAX_ATTEMPTS - pins[sender_id].get("failed_attempts", 0)
        
        if remaining <= 0:
            send_and_track(
                m.chat.id,
                f"🔒 **ACCOUNT LOCKED**\n\n"
                f"Too many failed attempts.\n\n"
                f"Your account is locked for {PIN_LOCKOUT_MINUTES} minutes.",
                reply_markup=earner_menu(m.chat.id),
                parse_mode="Markdown"
            )
            user_state.pop(m.chat.id, None)
            temp_data.pop(m.chat.id, None)
        else:
            send_and_track(
                m.chat.id,
                f"❌ **INCORRECT PIN**\n\n"
                f"Attempts remaining: {remaining}\n\n"
                f"Enter your PIN again:",
                reply_markup=back_button(),
                parse_mode="Markdown"
            )
        return
    
    # PIN correct - reset failed attempts
    reset_failed_attempts(sender_id)
    
    # Show confirmation
    data = temp_data[m.chat.id]
    receiver_id = data["transfer_receiver"]
    receiver_name = data["receiver_name"]
    amount = data["transfer_amount"]
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Confirm Transfer", callback_data="execute_transfer"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_transfer")
    )
    
    msg = bot.send_message(
        m.chat.id,
        f"📋 **CONFIRM TRANSFER**\n\n"
        f"Send ₦{amount:.2f} to:\n\n"
        f"👤 Name: {receiver_name}\n"
        f"🆔 ID: `{receiver_id}`\n\n"
        f"Confirm this transfer?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id
    user_state.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "cancel_transfer")
def cancel_transfer(c):
    bot.edit_message_text(
        "❌ Transfer cancelled.",
        c.message.chat.id,
        c.message.message_id
    )
    temp_data.pop(c.message.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "execute_transfer")
def execute_transfer(c):
    sender_id = str(c.message.chat.id)
    data = temp_data.get(c.message.chat.id)
    
    if not data:
        bot.answer_callback_query(c.id, "❌ Session expired!")
        return
    
    receiver_id = data["transfer_receiver"]
    receiver_name = data["receiver_name"]
    amount = data["transfer_amount"]
    
    # ATOMIC TRANSACTION - Load wallets
    wallets = load(WALLETS_FILE)
    
    # Final security checks
    if sender_id not in wallets or receiver_id not in wallets:
        bot.edit_message_text(
            "❌ Transfer failed: User not found.",
            c.message.chat.id,
            c.message.message_id
        )
        temp_data.pop(c.message.chat.id, None)
        return
    
    if wallets[sender_id]["naira"] < amount:
        bot.edit_message_text(
            "❌ Transfer failed: Insufficient balance.",
            c.message.chat.id,
            c.message.message_id
        )
        temp_data.pop(c.message.chat.id, None)
        return
    
    # Execute transfer atomically
    wallets[sender_id]["naira"] -= amount
    wallets[receiver_id]["naira"] += amount
    
    # Save ONCE
    save(WALLETS_FILE, wallets)
    
    # Log transfer
    log_id = log_transfer_event(
        "p2p_transfer",
        sender_id,
        receiver_id,
        amount,
        "success",
        "User-to-user transfer"
    )
    
    # Increment daily count
    increment_transfer_count(sender_id)
    
    # Get sender name
    users = load(USERS_FILE)
    sender_name = users.get(sender_id, {}).get("name", "User")
    
    # Notify sender
    bot.edit_message_text(
        f"✅ **TRANSFER SUCCESSFUL!**\n\n"
        f"💰 Amount: ₦{amount:.2f}\n"
        f"👤 To: {receiver_name}\n"
        f"🆔 ID: `{receiver_id}`\n\n"
        f"💵 New Balance: ₦{wallets[sender_id]['naira']:.2f}\n\n"
        f"📝 Transfer ID: `{log_id}`",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )
    
    # Notify receiver
    try:
        bot.send_message(
            receiver_id,
            f"💰 **MONEY RECEIVED!**\n\n"
            f"You received ₦{amount:.2f} from:\n\n"
            f"👤 Name: {sender_name}\n"
            f"🆔 ID: `{sender_id}`\n\n"
            f"💵 New Balance: ₦{wallets[receiver_id]['naira']:.2f}\n\n"
            f"📝 Transfer ID: `{log_id}`",
            parse_mode="Markdown"
        )
    except:
        pass
    
    temp_data.pop(c.message.chat.id, None)
    bot.answer_callback_query(c.id, "✅ Transfer completed!")

# ================= ADMIN: TRANSFER REVERSAL =================

@bot.message_handler(func=lambda m: m.text == "🔄 Transfer Reversal" and m.chat.id == ADMIN_ID)
def transfer_reversal_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        "🔄 **TRANSFER REVERSAL**\n\n"
        "Enter Transfer ID (from transfer logs):\n\n"
        "⚠️ This will reverse the transfer and return money to sender.",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[m.chat.id] = "reversal_enter_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "reversal_enter_id" and m.chat.id == ADMIN_ID)
def reversal_enter_id(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    log_id = m.text.strip()
    audit_logs = load(TRANSFER_AUDIT_FILE)
    
    if log_id not in audit_logs:
        send_and_track(m.chat.id, "❌ Transfer ID not found!\n\nTry again:", reply_markup=back_button())
        return
    
    log_entry = audit_logs[log_id]
    
    # Check if it's a p2p transfer
    if log_entry["type"] != "p2p_transfer":
        send_and_track(m.chat.id, "❌ This is not a P2P transfer!\n\nTry again:", reply_markup=back_button())
        return
    
    # Check if already reversed
    if log_entry["status"] == "reversed":
        send_and_track(m.chat.id, "❌ This transfer has already been reversed!\n\nTry again:", reply_markup=back_button())
        return
    
    sender_id = log_entry["from"]
    receiver_id = log_entry["to"]
    amount = log_entry["amount"]
    
    users = load(USERS_FILE)
    sender_name = users.get(sender_id, {}).get("name", "Unknown")
    receiver_name = users.get(receiver_id, {}).get("name", "Unknown")
    
    wallets = load(WALLETS_FILE)
    receiver_balance = wallets.get(receiver_id, {}).get("naira", 0)
    
    temp_data[m.chat.id] = {"reversing_log": log_id}
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Reverse Transfer", callback_data="confirm_reversal"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_reversal")
    )
    
    msg = bot.send_message(
        m.chat.id,
        f"🔄 **CONFIRM REVERSAL**\n\n"
        f"Transfer ID: `{log_id}`\n\n"
        f"📊 Transfer Details:\n"
        f"From: {sender_name} (`{sender_id}`)\n"
        f"To: {receiver_name} (`{receiver_id}`)\n"
        f"Amount: ₦{amount:.2f}\n"
        f"Date: {log_entry['time'][:16]}\n\n"
        f"💰 Receiver Current Balance: ₦{receiver_balance:.2f}\n\n"
        f"⚠️ This will:\n"
        f"• Deduct ₦{amount:.2f} from receiver\n"
        f"• Return ₦{amount:.2f} to sender\n\n"
        f"Confirm reversal?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id
    admin_state.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "cancel_reversal")
def cancel_reversal(c):
    bot.edit_message_text(
        "❌ Reversal cancelled.",
        c.message.chat.id,
        c.message.message_id
    )
    temp_data.pop(c.message.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "confirm_reversal")
def confirm_reversal(c):
    log_id = temp_data.get(c.message.chat.id, {}).get("reversing_log")
    
    if not log_id:
        bot.answer_callback_query(c.id, "❌ Session expired!")
        return
    
    audit_logs = load(TRANSFER_AUDIT_FILE)
    log_entry = audit_logs[log_id]
    
    sender_id = log_entry["from"]
    receiver_id = log_entry["to"]
    amount = log_entry["amount"]
    
    # Load wallets
    wallets = load(WALLETS_FILE)
    
    # Check if receiver has enough balance
    if wallets[receiver_id]["naira"] < amount:
        bot.edit_message_text(
            f"❌ **REVERSAL FAILED**\n\n"
            f"Receiver doesn't have enough balance.\n\n"
            f"Required: ₦{amount:.2f}\n"
            f"Receiver has: ₦{wallets[receiver_id]['naira']:.2f}",
            c.message.chat.id,
            c.message.message_id,
            parse_mode="Markdown"
        )
        temp_data.pop(c.message.chat.id, None)
        return
    
    # Execute reversal atomically
    wallets[receiver_id]["naira"] -= amount
    wallets[sender_id]["naira"] += amount
    
    # Save ONCE
    save(WALLETS_FILE, wallets)
    
    # Update original log
    audit_logs[log_id]["status"] = "reversed"
    audit_logs[log_id]["reversed_at"] = datetime.now().isoformat()
    audit_logs[log_id]["reversed_by"] = ADMIN_ID
    save(TRANSFER_AUDIT_FILE, audit_logs)
    
    # Log reversal
    log_transfer_event(
        "transfer_reversal",
        receiver_id,
        sender_id,
        amount,
        "success",
        f"Admin reversed transfer {log_id}",
        ADMIN_ID
    )
    
    users = load(USERS_FILE)
    sender_name = users.get(sender_id, {}).get("name", "Unknown")
    receiver_name = users.get(receiver_id, {}).get("name", "Unknown")
    
    # Notify both users
    try:
        bot.send_message(
            sender_id,
            f"💰 **TRANSFER REVERSED**\n\n"
            f"A transfer has been reversed by admin.\n\n"
            f"₦{amount:.2f} has been returned to your account.\n\n"
            f"New Balance: ₦{wallets[sender_id]['naira']:.2f}",
            parse_mode="Markdown"
        )
    except:
        pass
    
    try:
        bot.send_message(
            receiver_id,
            f"⚠️ **TRANSFER REVERSED**\n\n"
            f"A transfer has been reversed by admin.\n\n"
            f"₦{amount:.2f} has been deducted from your account.\n\n"
            f"New Balance: ₦{wallets[receiver_id]['naira']:.2f}",
            parse_mode="Markdown"
        )
    except:
        pass
    
    bot.edit_message_text(
        f"✅ **REVERSAL COMPLETED!**\n\n"
        f"Transfer ID: `{log_id}`\n\n"
        f"Amount: ₦{amount:.2f}\n"
        f"Returned to: {sender_name} (`{sender_id}`)\n"
        f"Deducted from: {receiver_name} (`{receiver_id}`)\n\n"
        f"Both users have been notified.",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )
    
    temp_data.pop(c.message.chat.id, None)
    bot.answer_callback_query(c.id, "✅ Transfer reversed!")

# ================= ADMIN: PIN MANAGEMENT =================

@bot.message_handler(func=lambda m: m.text == "🔐 PIN Management" and m.chat.id == ADMIN_ID)
def pin_management_menu(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("🔓 Reset User PIN")
    kb.row("🔍 View PIN Status")
    kb.row("🔙 Back")
    
    send_and_track(
        m.chat.id,
        "🔐 **PIN MANAGEMENT**\n\n"
        "Select an option:",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[m.chat.id] = "pin_management_select"

@bot.message_handler(func=lambda m: m.text == "🔓 Reset User PIN" and admin_state.get(m.chat.id) == "pin_management_select" and m.chat.id == ADMIN_ID)
def reset_pin_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        "🔓 **RESET USER PIN**\n\n"
        "Enter User ID:",
        reply_markup=kb
    )
    admin_state[m.chat.id] = "reset_pin_enter_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "reset_pin_enter_id" and m.chat.id == ADMIN_ID)
def reset_pin_confirm(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "pin_management_select"
        return pin_management_menu(m)
    
    if not validate_user_id(m.text):
        send_and_track(m.chat.id, "❌ Invalid User ID!\n\nTry again:", reply_markup=back_button())
        return
    
    user_id = str(m.text)
    users = load(USERS_FILE)
    
    if user_id not in users:
        send_and_track(m.chat.id, f"❌ User ID {user_id} not found!\n\nTry again:", reply_markup=back_button())
        return
    
    pins = load(PIN_FILE)
    
    if user_id not in pins or not pins[user_id].get("pin_hash"):
        send_and_track(m.chat.id, "❌ This user doesn't have a PIN set!\n\nTry again:", reply_markup=back_button())
        return
    
    user_name = users[user_id].get("name", "Unknown")
    
    temp_data[m.chat.id] = {"resetting_pin_user": user_id}
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Reset PIN", callback_data="confirm_pin_reset"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_pin_reset")
    )
    
    msg = bot.send_message(
        m.chat.id,
        f"🔓 **CONFIRM PIN RESET**\n\n"
        f"User: {user_name}\n"
        f"ID: `{user_id}`\n\n"
        f"⚠️ This will:\n"
        f"• Delete their current PIN\n"
        f"• Force them to create a new PIN\n"
        f"• Unlock their account if locked\n\n"
        f"Confirm PIN reset?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id
    admin_state.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "cancel_pin_reset")
def cancel_pin_reset(c):
    bot.edit_message_text(
        "❌ PIN reset cancelled.",
        c.message.chat.id,
        c.message.message_id
    )
    temp_data.pop(c.message.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "confirm_pin_reset")
def confirm_pin_reset(c):
    user_id = temp_data.get(c.message.chat.id, {}).get("resetting_pin_user")
    
    if not user_id:
        bot.answer_callback_query(c.id, "❌ Session expired!")
        return
    
    pins = load(PIN_FILE)
    users = load(USERS_FILE)
    
    # Delete PIN
    pins[user_id] = {
        "pin_hash": None,
        "created": None,
        "failed_attempts": 0,
        "lockout_until": None
    }
    save(PIN_FILE, pins)
    
    # Log event
    log_transfer_event("pin_reset", user_id, None, 0, "success", "Admin reset user PIN", ADMIN_ID)
    
    user_name = users[user_id].get("name", "Unknown")
    
    # Notify user
    try:
        bot.send_message(
            user_id,
            "🔓 **PIN RESET BY ADMIN**\n\n"
            "Your PIN has been reset by an administrator.\n\n"
            "You need to create a new PIN to use the transfer feature.\n\n"
            "Go to Transfer menu to set a new PIN.",
            parse_mode="Markdown"
        )
    except:
        pass
    
    bot.edit_message_text(
        f"✅ **PIN RESET COMPLETED!**\n\n"
        f"User: {user_name}\n"
        f"ID: `{user_id}`\n\n"
        f"Their PIN has been deleted.\n"
        f"User will need to create a new PIN.",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )
    
    temp_data.pop(c.message.chat.id, None)
    bot.answer_callback_query(c.id, "✅ PIN reset!")

@bot.message_handler(func=lambda m: m.text == "🔍 View PIN Status" and admin_state.get(m.chat.id) == "pin_management_select" and m.chat.id == ADMIN_ID)
def view_pin_status_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        "🔍 **VIEW PIN STATUS**\n\n"
        "Enter User ID:",
        reply_markup=kb
    )
    admin_state[m.chat.id] = "view_pin_status_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "view_pin_status_id" and m.chat.id == ADMIN_ID)
def view_pin_status(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "pin_management_select"
        return pin_management_menu(m)
    
    if not validate_user_id(m.text):
        send_and_track(m.chat.id, "❌ Invalid User ID!\n\nTry again:", reply_markup=back_button())
        return
    
    user_id = str(m.text)
    users = load(USERS_FILE)
    
    if user_id not in users:
        send_and_track(m.chat.id, f"❌ User ID {user_id} not found!\n\nTry again:", reply_markup=back_button())
        return
    
    pins = load(PIN_FILE)
    user_name = users[user_id].get("name", "Unknown")
    
    text = f"🔍 **PIN STATUS**\n\n"
    text += f"User: {user_name}\n"
    text += f"ID: `{user_id}`\n\n"
    
    if user_id not in pins or not pins[user_id].get("pin_hash"):
        text += "❌ **Status:** No PIN set\n"
    else:
        pin_data = pins[user_id]
        text += "✅ **Status:** PIN created\n"
        
        if pin_data.get("created"):
            text += f"📅 Created: {pin_data['created'][:16]}\n"
        
        failed = pin_data.get("failed_attempts", 0)
        text += f"❌ Failed Attempts: {failed}/{PIN_MAX_ATTEMPTS}\n"
        
        if pin_data.get("lockout_until"):
            lockout_time = datetime.fromisoformat(pin_data["lockout_until"])
            if datetime.now() < lockout_time:
                remaining = (lockout_time - datetime.now()).seconds // 60
                text += f"🔒 **LOCKED** - {remaining} minutes remaining\n"
            else:
                text += "🔓 Not locked\n"
        else:
            text += "🔓 Not locked\n"
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

# ================= ADMIN: TRANSFER LOGS =================

@bot.message_handler(func=lambda m: m.text == "📊 Transfer Logs" and m.chat.id == ADMIN_ID)
def view_transfer_logs(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    audit_logs = load(TRANSFER_AUDIT_FILE)
    users = load(USERS_FILE)
    
    # Get recent transfers
    recent = sorted(
        [(k, v) for k, v in audit_logs.items() if v["type"] == "p2p_transfer"],
        key=lambda x: x[1]["time"],
        reverse=True
    )[:10]
    
    if not recent:
        send_and_track(
            m.chat.id,
            "📊 **TRANSFER LOGS**\n\n"
            "No transfers found.",
            reply_markup=back_button(),
            parse_mode="Markdown"
        )
        return
    
    text = "📊 **RECENT TRANSFERS**\n\n"
    
    for log_id, log_data in recent:
        sender_name = users.get(log_data["from"], {}).get("name", "Unknown")
        receiver_name = users.get(log_data["to"], {}).get("name", "Unknown")
        status_emoji = "✅" if log_data["status"] == "success" else "❌" if log_data["status"] == "reversed" else "⚠️"
        
        text += f"{status_emoji} **Transfer**\n"
        text += f"ID: `{log_id}`\n"
        text += f"From: {sender_name} (`{log_data['from']}`)\n"
        text += f"To: {receiver_name} (`{log_data['to']}`)\n"
        text += f"Amount: ₦{log_data['amount']:.2f}\n"
        text += f"Time: {log_data['time'][:16]}\n"
        text += f"Status: {log_data['status'].upper()}\n"
        text += "\n"
    
    if len(audit_logs) > 10:
        text += f"... and {len(audit_logs) - 10} more transfers\n"
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

# ================= MY INFORMATION BUTTON =================

@bot.message_handler(func=lambda m: m.text == "ℹ️ My Information")
def show_my_information(m):
    user_id = str(m.chat.id)
    
    if not rate_limit_check(user_id, "info"):
        bot.send_message(m.chat.id, "⚠️ Please wait a moment before requesting information again.")
        return
    
    delete_message_safe(m.chat.id, m.message_id)
    
    users = load(USERS_FILE)
    wallet = get_wallet(user_id)
    
    if not wallet:
        send_and_track(m.chat.id, "❌ Error loading wallet information.", reply_markup=back_button())
        return
    
    bank_data = load(BANK_FILE)
    withdrawals = load(WITHDRAWALS_FILE)
    referrals = load(REFERRALS_FILE)
    exchanges = load(EXCHANGES_FILE)
    pins = load(PIN_FILE)
    
    user_info = users.get(user_id, {})
    bank_info = bank_data.get(user_id, {})
    ref_list = referrals.get(user_id, [])
    
    user_withdrawals = [w for w in withdrawals.values() if w["user_id"] == user_id]
    total_withdrawn_naira = sum(w["total"] for w in user_withdrawals if w["currency"] == "naira" and w["status"] == "approved")
    total_withdrawn_dollar = sum(w["total"] for w in user_withdrawals if w["currency"] == "usdt" and w["status"] == "approved")
    pending_withdrawals = len([w for w in user_withdrawals if w["status"] == "pending"])
    
    user_exchanges = [e for e in exchanges.values() if e["user_id"] == user_id]
    completed_exchanges = len([e for e in user_exchanges if e["status"] == "completed"])
    pending_exchanges = len([e for e in user_exchanges if e["status"] == "pending"])
    
    # Transfer statistics
    today_transfers = get_today_transfer_count(user_id)
    audit_logs = load(TRANSFER_AUDIT_FILE)
    total_sent = sum(log["amount"] for log in audit_logs.values() 
                     if log["type"] == "p2p_transfer" and log["from"] == user_id and log["status"] == "success")
    total_received = sum(log["amount"] for log in audit_logs.values() 
                        if log["type"] == "p2p_transfer" and log["to"] == user_id and log["status"] == "success")
    
    ref_link = f"{BOT_LINK}?start={user_id}"
    
    text = (
        f"ℹ️ **YOUR COMPLETE INFORMATION**\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👤 **PERSONAL INFO**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📛 Name: {user_info.get('name', 'Unknown')}\n"
        f"🆔 User ID: `{user_id}`\n"
        f"📅 Joined: {user_info.get('joined', 'N/A')[:16]}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💰 **WALLET BALANCE**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"₦ Naira: ₦{wallet['naira']:.2f}\n"
        f"💵 USDT: ${wallet['dollar']:.2f}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📊 **TASK STATISTICS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"✅ Completed: {wallet['completed_tasks']}\n"
        f"⏳ Pending: {wallet['pending_tasks']}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💸 **TRANSFER STATISTICS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📤 Total Sent: ₦{total_sent:.2f}\n"
        f"📥 Total Received: ₦{total_received:.2f}\n"
        f"📊 Today: {today_transfers}/{MAX_TRANSFERS_PER_DAY}\n"
    )
    
    # PIN status
    if user_id in pins and pins[user_id].get("pin_hash"):
        text += f"🔐 PIN: Set ✅\n\n"
    else:
        text += f"🔐 PIN: Not Set ❌\n\n"
    
    text += (
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👥 **REFERRALS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👤 Total Referrals: {len(ref_list)}\n"
        f"💰 Earned (Naira): ₦{wallet['referral_naira']:.2f}\n"
        f"💵 Earned (USDT): ${wallet['referral_dollar']:.2f}\n"
        f"🔗 Your Referral Link:\n`{ref_link}`\n\n"
    )
    
    text += (
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💳 **PAYMENT DETAILS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
    )
    
    if bank_info:
        text += (
            f"📋 Type: {bank_info.get('type', 'N/A')}\n"
            f"📝 Details:\n{bank_info.get('details', 'Not set')}\n"
            f"🕐 Updated: {bank_info.get('updated', 'N/A')[:16]}\n\n"
        )
    else:
        text += "⚠️ Not set yet\n\n"
    
    text += (
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💸 **WITHDRAWAL HISTORY**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"✅ Total Withdrawn:\n"
        f"   ₦ Naira: ₦{total_withdrawn_naira:.2f}\n"
        f"   💵 USDT: ${total_withdrawn_dollar:.2f}\n"
        f"⏳ Pending Withdrawals: {pending_withdrawals}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💱 **EXCHANGE HISTORY**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"✅ Completed Exchanges: {completed_exchanges}\n"
        f"⏳ Pending Exchanges: {pending_exchanges}\n\n"
    )
    
    if ref_list:
        text += (
            f"━━━━━━━━━━━━━━━━━━\n"
            f"📋 **YOUR REFERRALS**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
        )
        for idx, ref in enumerate(ref_list[:5], 1):
            status = "✅ Rewarded" if ref["reward_paid"] else f"⏳ {ref['tasks_completed']}/10 tasks"
            text += f"{idx}. {ref['name']} - {status}\n"
        
        if len(ref_list) > 5:
            text += f"\n... and {len(ref_list) - 5} more referrals\n"
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

# ================= ADVERTISER: CONTACT ADMIN =================

@bot.message_handler(func=lambda m: m.text == "💬 Contact Admin")
def contact_admin(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("💬 Message Admin", url=f"https://t.me/{ADMIN_USERNAME.replace('@', '').replace('https://t.me/', '')}"))
    
    send_and_track(
        m.chat.id,
        f"📢 **ADVERTISER INFORMATION**\n\n"
        f"To create advertising campaigns, you need to:\n\n"
        f"1️⃣ Contact our admin directly\n"
        f"2️⃣ Discuss your advertising needs\n"
        f"3️⃣ Make payment to admin\n"
        f"4️⃣ Admin will create tasks for you\n\n"
        f"👤 Admin Contact: {ADMIN_USERNAME}\n\n"
        f"Click the button below to start:",
        reply_markup=kb,
        parse_mode="Markdown"
    )

# ================= CURRENCY EXCHANGE =================

@bot.message_handler(func=lambda m: m.text == "💱 Exchange Currency")
def exchange_currency_menu(m):
    if not rate_limit_check(m.chat.id, "exchange"):
        bot.send_message(m.chat.id, "⚠️ Please wait a moment before making another exchange request.")
        return
    
    delete_message_safe(m.chat.id, m.message_id)
    
    w = get_wallet(m.chat.id)
    
    if not w:
        send_and_track(m.chat.id, "❌ Error loading wallet.", reply_markup=back_button())
        return
    
    text = (
        f"💱 **CURRENCY EXCHANGE**\n\n"
        f"💰 Your Current Balances:\n"
        f"₦ Naira: ₦{w['naira']:.2f}\n"
        f"💵 USDT: ${w['dollar']:.2f}\n\n"
        f"Select exchange type:"
    )
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("₦ → $ Exchange Naira to USDT")
    kb.row("$ → ₦ Exchange USDT to Naira")
    kb.row("🔙 Back")
    
    send_and_track(m.chat.id, text, reply_markup=kb, parse_mode="Markdown")
    user_state[m.chat.id] = "select_exchange_type"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "select_exchange_type")
def select_exchange_type(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "💸 Earner Menu", reply_markup=earner_menu(m.chat.id))
    
    if "Naira to USDT" in m.text:
        temp_data[m.chat.id] = {"exchange_type": "naira_to_dollar"}
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        send_and_track(
            m.chat.id,
            "💰 **EXCHANGE NAIRA TO USDT**\n\n"
            "Enter the amount in Naira (₦) you want to exchange:",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "enter_exchange_amount"
    
    elif "USDT to Naira" in m.text:
        temp_data[m.chat.id] = {"exchange_type": "dollar_to_naira"}
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        send_and_track(
            m.chat.id,
            "💵 **EXCHANGE USDT TO NAIRA**\n\n"
            "Enter the amount in USDT ($) you want to exchange:",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "enter_exchange_amount"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "enter_exchange_amount")
def enter_exchange_amount(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return exchange_currency_menu(m)
    
    if not validate_amount(m.text):
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a valid number:", reply_markup=back_button())
        return
    
    try:
        amount = float(m.text)
    except:
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a number:", reply_markup=back_button())
        return
    
    user_id = str(m.chat.id)
    w = get_wallet(user_id)
    
    if not w:
        send_and_track(m.chat.id, "❌ Error loading wallet.", reply_markup=back_button())
        return
    
    exchange_type = temp_data[m.chat.id]["exchange_type"]
    
    if exchange_type == "naira_to_dollar":
        if amount > w["naira"]:
            send_and_track(
                m.chat.id,
                f"❌ Insufficient Naira balance!\n\n"
                f"You have: ₦{w['naira']:.2f}\n"
                f"You need: ₦{amount:.2f}",
                reply_markup=back_button(),
                parse_mode="Markdown"
            )
            return
        from_currency = "Naira"
        to_currency = "USDT"
        from_symbol = "₦"
        to_symbol = "$"
    else:
        if amount > w["dollar"]:
            send_and_track(
                m.chat.id,
                f"❌ Insufficient USDT balance!\n\n"
                f"You have: ${w['dollar']:.2f}\n"
                f"You need: ${amount:.2f}",
                reply_markup=back_button(),
                parse_mode="Markdown"
            )
            return
        from_currency = "USDT"
        to_currency = "Naira"
        from_symbol = "$"
        to_symbol = "₦"
    
    temp_data[m.chat.id]["amount"] = amount
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Confirm Exchange", callback_data=f"confirm_exchange"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_exchange")
    )
    
    msg = bot.send_message(
        m.chat.id,
        f"💱 **EXCHANGE CONFIRMATION**\n\n"
        f"From: {from_symbol}{amount:.2f} {from_currency}\n"
        f"To: {to_symbol}? {to_currency}\n\n"
        f"⏰ **Processing Time:** Up to 1 to 2 hours\n\n"
        f"Exchange rate will be determined by Our Agent.\n\n"
        f"Confirm exchange request?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id
    user_state.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "confirm_exchange")
def confirm_exchange(c):
    user_id = str(c.message.chat.id)
    data = temp_data.get(c.message.chat.id)
    
    if not data:
        bot.answer_callback_query(c.id, "❌ Session expired!")
        return
    
    amount = data["amount"]
    exchange_type = data["exchange_type"]
    
    if not validate_amount(amount):
        bot.answer_callback_query(c.id, "❌ Invalid amount!")
        return
    
    exchanges = load(EXCHANGES_FILE)
    exchange_id = f"ex_{user_id}_{int(datetime.now().timestamp())}"
    
    exchanges[exchange_id] = {
        "user_id": user_id,
        "exchange_type": exchange_type,
        "amount": amount,
        "status": "pending",
        "requested": str(datetime.now())
    }
    save(EXCHANGES_FILE, exchanges)
    
    users = load(USERS_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    wallet = get_wallet(user_id)
    
    if exchange_type == "naira_to_dollar":
        from_text = f"₦{amount:.2f} Naira"
        to_text = "USDT ($)"
    else:
        from_text = f"${amount:.2f} USDT"
        to_text = "Naira (₦)"
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Complete Exchange", callback_data=f"complete_exchange_{exchange_id}"),
        types.InlineKeyboardButton("❌ Cancel", callback_data=f"cancel_exchange_req_{exchange_id}")
    )
    
    bot.send_message(
        ADMIN_ID,
        f"💱 **NEW EXCHANGE REQUEST**\n\n"
        f"👤 User: {user_name}\n"
        f"🆔 ID: `{user_id}`\n\n"
        f"📊 Exchange Details:\n"
        f"From: {from_text}\n"
        f"To: {to_text}\n\n"
        f"💰 Current Balances:\n"
        f"₦ Naira: ₦{wallet['naira']:.2f}\n"
        f"💵 USDT: ${wallet['dollar']:.2f}\n\n"
        f"⏰ Requested: {str(datetime.now())[:16]}",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    
    bot.edit_message_text(
        "✅ **EXCHANGE REQUEST SUBMITTED!**\n\n"
        "Your currency exchange request has been sent to admin.\n\n"
        "⏰ **Processing Time:** Up to 1 to 2 hours\n\n"
        "You will be notified once the exchange is completed.\n\n"
        "Thank you for your patience! 🙏",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )
    
    temp_data.pop(c.message.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "cancel_exchange")
def cancel_exchange(c):
    bot.edit_message_text(
        "❌ Exchange request cancelled.",
        c.message.chat.id,
        c.message.message_id
    )
    temp_data.pop(c.message.chat.id, None)

# ================= ADMIN: EXCHANGE REQUESTS =================

@bot.message_handler(func=lambda m: m.text == "💱 Exchange Requests" and m.chat.id == ADMIN_ID)
def view_exchange_requests(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    exchanges = load(EXCHANGES_FILE)
    users = load(USERS_FILE)
    
    pending = []
    completed = []
    cancelled = []
    
    for ex_id, ex_data in exchanges.items():
        if ex_data["status"] == "pending":
            pending.append((ex_id, ex_data))
        elif ex_data["status"] == "completed":
            completed.append((ex_id, ex_data))
        else:
            cancelled.append((ex_id, ex_data))
    
    text = f"💱 **EXCHANGE REQUESTS**\n\n"
    text += f"⏳ Pending: {len(pending)}\n"
    text += f"✅ Completed: {len(completed)}\n"
    text += f"❌ Cancelled: {len(cancelled)}\n\n"
    
    if pending:
        text += "━━━━━━━━━━━━━━━━━━\n\n"
        text += "⏳ **PENDING REQUESTS:**\n\n"
        for ex_id, ex_data in pending[:5]:
            user_name = users.get(ex_data["user_id"], {}).get("name", "Unknown")
            
            if ex_data["exchange_type"] == "naira_to_dollar":
                from_text = f"₦{ex_data['amount']:.2f}"
                to_text = "$"
            else:
                from_text = f"${ex_data['amount']:.2f}"
                to_text = "₦"
            
            text += f"👤 {user_name}\n"
            text += f"🆔 `{ex_data['user_id']}`\n"
            text += f"💱 {from_text} → {to_text}\n"
            text += f"📅 {ex_data['requested'][:16]}\n"
            text += f"ID: `{ex_id}`\n\n"
    else:
        text += "\n✅ No pending exchange requests!"
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

@bot.callback_query_handler(func=lambda c: c.data.startswith("complete_exchange_"))
def complete_exchange_admin(c):
    exchange_id = c.data.replace("complete_exchange_", "")
    
    exchanges = load(EXCHANGES_FILE)
    if exchange_id not in exchanges:
        bot.answer_callback_query(c.id, "❌ Exchange request not found!")
        return
    
    exchange = exchanges[exchange_id]
    if exchange["status"] != "pending":
        bot.answer_callback_query(c.id, "⚠️ Already processed!")
        return
    
    temp_data[c.message.chat.id] = {"processing_exchange": exchange_id}
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    bot.send_message(
        c.message.chat.id,
        f"💱 **PROCESSING EXCHANGE**\n\n"
        f"Exchange ID: `{exchange_id}`\n\n"
        f"Enter the amount user will receive:\n"
        f"(The exact amount after applying your exchange rate)",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[c.message.chat.id] = "enter_exchange_rate"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "enter_exchange_rate" and m.chat.id == ADMIN_ID)
def process_exchange_rate(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    if not validate_amount(m.text):
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a positive number:", reply_markup=back_button())
        return
    
    try:
        received_amount = float(m.text)
    except:
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a number:", reply_markup=back_button())
        return
    
    exchange_id = temp_data[m.chat.id]["processing_exchange"]
    exchanges = load(EXCHANGES_FILE)
    exchange = exchanges[exchange_id]
    
    user_id = exchange["user_id"]
    amount = exchange["amount"]
    exchange_type = exchange["exchange_type"]
    
    if exchange_type == "naira_to_dollar":
        update_wallet(user_id, "naira", -amount)
        update_wallet(user_id, "dollar", received_amount)
        from_text = f"₦{amount:.2f}"
        to_text = f"${received_amount:.2f}"
    else:
        update_wallet(user_id, "dollar", -amount)
        update_wallet(user_id, "naira", received_amount)
        from_text = f"${amount:.2f}"
        to_text = f"₦{received_amount:.2f}"
    
    exchange["status"] = "completed"
    exchange["received_amount"] = received_amount
    exchange["completed_at"] = str(datetime.now())
    exchanges[exchange_id] = exchange
    save(EXCHANGES_FILE, exchanges)
    
    users = load(USERS_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    bot.send_message(
        user_id,
        f"✅ **EXCHANGE COMPLETED!**\n\n"
        f"Your currency exchange has been completed successfully! 🎉\n\n"
        f"💱 Exchange Details:\n"
        f"From: {from_text}\n"
        f"Received: {to_text}\n\n"
        f"Please check your balance to confirm the update.\n\n"
        f"Thank you for using our service! 💰",
        parse_mode="Markdown"
    )
    
    send_and_track(
        m.chat.id,
        f"✅ Exchange completed successfully!\n\n"
        f"User {user_name} has been notified.",
        reply_markup=admin_menu()
    )
    
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data.startswith("cancel_exchange_req_"))
def cancel_exchange_request(c):
    exchange_id = c.data.replace("cancel_exchange_req_", "")
    
    exchanges = load(EXCHANGES_FILE)
    if exchange_id not in exchanges:
        bot.answer_callback_query(c.id, "❌ Exchange request not found!")
        return
    
    exchange = exchanges[exchange_id]
    
    if exchange["status"] != "pending":
        bot.answer_callback_query(c.id, "⚠️ Already processed!")
        return
    
    user_id = exchange["user_id"]
    
    exchange["status"] = "cancelled"
    exchange["cancelled_at"] = str(datetime.now())
    exchanges[exchange_id] = exchange
    save(EXCHANGES_FILE, exchanges)
    
    users = load(USERS_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    bot.send_message(
        user_id,
        "❌ **EXCHANGE REQUEST CANCELLED**\n\n"
        "Your currency exchange request has been cancelled by admin.\n\n"
        "Please contact support for more information.",
        parse_mode="Markdown"
    )
    
    try:
        bot.edit_message_text(
            f"❌ **EXCHANGE CANCELLED**\n\n{c.message.text}\n\n❌ Cancelled at: {str(datetime.now())[:16]}",
            c.message.chat.id,
            c.message.message_id,
            parse_mode="Markdown"
        )
    except:
        pass
    
    bot.answer_callback_query(c.id, "✅ Exchange cancelled!")

# ================= PAYMENT DETAILS =================

@bot.message_handler(func=lambda m: m.text == "💳 Payment Details")
def payment_details_menu(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    bank_data = load(BANK_FILE)
    user_id = str(m.chat.id)
    
    if user_id in bank_data:
        details = bank_data[user_id]
        
        text = (
            f"💳 **YOUR PAYMENT DETAILS**\n\n"
            f"📋 Type: {details.get('type', 'N/A')}\n"
            f"📝 Details:\n{details.get('details', 'N/A')}\n\n"
            f"🕐 Last Updated: {details.get('updated', 'N/A')[:16]}\n\n"
            f"Want to update your payment details?"
        )
        
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("🔄 Update Payment Details")
        kb.row("🔙 Back")
        
        send_and_track(m.chat.id, text, reply_markup=kb, parse_mode="Markdown")
        user_state[m.chat.id] = "view_payment_details"
    else:
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("🏦 Bank Account", "🪙 Crypto Wallet")
        kb.row("🔙 Back")
        
        send_and_track(
            m.chat.id,
            "💳 **ADD PAYMENT DETAILS**\n\n"
            "Please select your preferred payment method:",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "select_payment_type"

@bot.message_handler(func=lambda m: m.text == "🔄 Update Payment Details" and user_state.get(m.chat.id) == "view_payment_details")
def update_payment_details(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("🏦 Bank Account", "🪙 Crypto Wallet")
    kb.row("🔙 Back")
    
    send_and_track(
        m.chat.id,
        "💳 **UPDATE PAYMENT DETAILS**\n\n"
        "Please select your preferred payment method:",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    user_state[m.chat.id] = "select_payment_type"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "select_payment_type")
def select_payment_type(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "💸 Earner Menu", reply_markup=earner_menu(m.chat.id))
    
    if m.text == "🏦 Bank Account":
        temp_data[m.chat.id] = {"payment_type": "Bank Account"}
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        send_and_track(
            m.chat.id,
            "🏦 **BANK ACCOUNT DETAILS**\n\n"
            "Please send your bank details in this format:\n\n"
            "Bank Name: [Your Bank]\n"
            "Account Number: [Your Account Number]\n"
            "Account Name: [Your Full Name]\n\n",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "enter_payment_details"
    
    elif m.text == "🪙 Crypto Wallet":
        temp_data[m.chat.id] = {"payment_type": "Crypto Wallet"}
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("Binance", "Other Wallet")
        kb.row("🔙 Back")
        
        send_and_track(
            m.chat.id,
            "🪙 **CRYPTO WALLET TYPE**\n\n"
            "Please select your wallet type:",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "select_crypto_type"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "select_crypto_type")
def select_crypto_type(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        temp_data.pop(m.chat.id, None)
        user_state[m.chat.id] = "select_payment_type"
        return payment_details_menu(m)
    
    if m.text == "Binance":
        temp_data[m.chat.id]["crypto_type"] = "Binance"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        send_and_track(
            m.chat.id,
            "🟡 **BINANCE ID**\n\n"
            "Please send your Binance ID:\n\n"
            "Example: 123456789",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "enter_payment_details"
    
    elif m.text == "Other Wallet":
        temp_data[m.chat.id]["crypto_type"] = "Other Wallet"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        send_and_track(
            m.chat.id,
            "🪙 **USDT WALLET ADDRESS (BEP20)**\n\n"
            "Please send your USDT BEP20 wallet address:\n\n"
            "Example: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
            reply_markup=kb,
            parse_mode="Markdown"
        )
        user_state[m.chat.id] = "enter_payment_details"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "enter_payment_details")
def save_payment_details(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        if temp_data[m.chat.id].get("payment_type") == "Crypto Wallet":
            user_state[m.chat.id] = "select_crypto_type"
            kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
            kb.row("Binance", "Other Wallet")
            kb.row("🔙 Back")
            return send_and_track(m.chat.id, "🪙 **CRYPTO WALLET TYPE**\n\nPlease select your wallet type:", reply_markup=kb, parse_mode="Markdown")
        else:
            user_state[m.chat.id] = "select_payment_type"
            return payment_details_menu(m)
    
    user_id = str(m.chat.id)
    bank_data = load(BANK_FILE)
    users = load(USERS_FILE)
    
    payment_type = temp_data[m.chat.id]["payment_type"]
    
    details_text = m.text[:500]
    
    if payment_type == "Bank Account":
        display_type = "Bank Account"
    else:
        crypto_type = temp_data[m.chat.id]["crypto_type"]
        display_type = f"Crypto Wallet - {crypto_type}"
    
    bank_data[user_id] = {
        "type": display_type,
        "details": details_text,
        "updated": str(datetime.now())
    }
    save(BANK_FILE, bank_data)
    
    user_name = users.get(user_id, {}).get("name", "Unknown")
    wallet = get_wallet(user_id)
    
    bot.send_message(
        ADMIN_ID,
        f"💳 **PAYMENT DETAILS {'UPDATED' if user_id in load(BANK_FILE) else 'ADDED'}**\n\n"
        f"👤 User: {user_name}\n"
        f"🆔 ID: `{user_id}`\n"
        f"📋 Type: {display_type}\n\n"
        f"📝 Details:\n{details_text}\n\n"
        f"💰 Balances:\n"
        f"₦ Naira: ₦{wallet['naira']:.2f}\n"
        f"💵 USDT: ${wallet['dollar']:.2f}",
        parse_mode="Markdown"
    )
    
    send_and_track(
        m.chat.id,
        "✅ **PAYMENT DETAILS SAVED!**\n\n"
        "Your payment details have been saved successfully! 💳\n\n"
        "You can now withdraw your earnings to this account/wallet.",
        reply_markup=earner_menu(m.chat.id),
        parse_mode="Markdown"
    )
    
    user_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)
# ================= EARNER: AVAILABLE TASKS =================

@bot.message_handler(func=lambda m: m.text == "🎯 Available Tasks")
def available_tasks(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    check_and_delete_completed_tasks()
    
    total, completed, remaining = count_tasks()
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("TikTok Tasks", "Facebook Tasks")
    kb.row("Instagram Tasks", "Twitter Tasks")
    kb.row("🔙 Back")
    
    text = (
        f"🎯 **TASKS OVERVIEW**\n\n"
        f"📊 Total Available Tasks: {total}\n"
        f"✅ Completed Tasks: {completed}\n"
        f"⏳ Remaining Tasks: {remaining}\n\n"
        f"Select Social Media Platform:"
    )
    
    send_and_track(m.chat.id, text, reply_markup=kb, parse_mode="Markdown")
    user_state[m.chat.id] = "select_platform"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "select_platform")
def select_task_platform(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "💸 Earner Menu", reply_markup=earner_menu(m.chat.id))
    
    platform_map = {
        "TikTok Tasks": "tiktok",
        "Facebook Tasks": "facebook",
        "Instagram Tasks": "instagram",
        "Twitter Tasks": "twitter"
    }
    
    platform = platform_map.get(m.text)
    if not platform:
        return
    
    temp_data[m.chat.id] = {"platform": platform}
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("👍 Like", "💬 Comment", "🔄 Share")
    kb.row("➕ Follow", "👥 Join Group", "📢 Join Channel")
    kb.row("🔙 Back")
    send_and_track(m.chat.id, f"Select task type for {m.text.replace(' Tasks', '')}:", reply_markup=kb)
    user_state[m.chat.id] = "select_task_type"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "select_task_type")
def select_task_type(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        temp_data.pop(m.chat.id, None)
        user_state[m.chat.id] = "select_platform"
        return available_tasks(m)
    
    task_map = {
        "👍 Like": "like",
        "💬 Comment": "comment",
        "🔄 Share": "share",
        "➕ Follow": "follow",
        "👥 Join Group": "join_group",
        "📢 Join Channel": "join_channel"
    }
    
    task_type = task_map.get(m.text)
    if not task_type:
        return
    
    platform = temp_data[m.chat.id]["platform"]
    temp_data[m.chat.id]["task_type"] = task_type
    
    tasks = load(TASKS_FILE)
    available = []
    user_id = str(m.chat.id)
    
    for task_id, task_data in tasks.items():
        if (task_data.get("platform") == platform and 
            task_data.get("task_type") == task_type and
            task_data.get("status") == "active"):
            
            completed_by = task_data.get("completed_by", [])
            max_users = task_data.get("max_users", 1)
            
            if user_id not in completed_by and len(completed_by) < max_users and not has_user_submitted_task(user_id, task_id):
                available.append((task_id, task_data))
    
    if not available:
        send_and_track(
            m.chat.id,
            "😔 No tasks available right now. Please check back later!",
            reply_markup=earner_menu(m.chat.id)
        )
        user_state.pop(m.chat.id, None)
        return
    
    msg_text = f"📋 **Available {m.text} Tasks:**\n\n"
    for task_id, task_data in available[:10]:
        price_str = f"₦{task_data.get('price_naira', 0)}" if task_data.get('currency') == 'naira' else f"${task_data.get('price_dollar', 0)}"
        completed_count = len(task_data.get("completed_by", []))
        max_users = task_data.get("max_users", 1)
        msg_text += f"🆔 Task ID: `{task_id}`\n💰 Reward: {price_str}\n👥 Slots: {completed_count}/{max_users}\n🔗 Link: {task_data.get('link', 'N/A')}\n\n"
    
    if len(available) > 10:
        msg_text += f"\n... and {len(available) - 10} more tasks available\n\n"
    
    msg_text += "To complete a task, send the Task ID:"
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, msg_text, parse_mode="Markdown", reply_markup=kb)
    user_state[m.chat.id] = "submit_task_id"

@bot.message_handler(func=lambda m: user_state.get(m.chat.id) == "submit_task_id")
def submit_task_id(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state[m.chat.id] = "select_task_type"
        temp_data_copy = temp_data.get(m.chat.id, {})
        platform = temp_data_copy.get("platform", "")
        
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("👍 Like", "💬 Comment", "🔄 Share")
        kb.row("➕ Follow", "👥 Join Group", "📢 Join Channel")
        kb.row("🔙 Back")
        
        platform_name = platform.title()
        return send_and_track(m.chat.id, f"Select task type for {platform_name}:", reply_markup=kb)
    
    task_id = m.text.strip()
    tasks = load(TASKS_FILE)
    
    if task_id not in tasks:
        send_and_track(m.chat.id, "❌ Invalid Task ID. Please try again:", reply_markup=back_button())
        return
    
    task = tasks[task_id]
    user_id = str(m.chat.id)
    
    if task.get("status") != "active":
        send_and_track(m.chat.id, "❌ This task is no longer available.", reply_markup=back_button())
        return
    
    if user_id in task.get("completed_by", []):
        send_and_track(m.chat.id, "⚠️ You have already completed this task!", reply_markup=back_button())
        return
    
    if has_user_submitted_task(user_id, task_id):
        send_and_track(m.chat.id, "⚠️ You have already submitted this task! Please wait for admin approval.", reply_markup=back_button())
        return
    
    if has_user_completed_similar_task(user_id, task.get("platform"), task.get("task_type"), task.get("link")):
        send_and_track(m.chat.id, "⚠️ You have already completed a similar task with the same link!", reply_markup=back_button())
        return
    
    max_users = task.get("max_users", 1)
    completed_by = task.get("completed_by", [])
    
    if len(completed_by) >= max_users:
        send_and_track(m.chat.id, "❌ This task has reached its user limit and is no longer available.", reply_markup=back_button())
        return
    
    temp_data[m.chat.id]["task_id"] = task_id
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(
        m.chat.id,
        f"📸 Please upload a screenshot as proof of task completion:\n\n"
        f"🔗 Task Link: {task.get('link', 'N/A')}",
        reply_markup=kb
    )
    user_state[m.chat.id] = "upload_proof"

@bot.message_handler(content_types=["photo"], func=lambda m: user_state.get(m.chat.id) == "upload_proof")
def upload_task_proof(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    task_id = temp_data[m.chat.id]["task_id"]
    user_id = str(m.chat.id)
    
    if not rate_limit_check(user_id, "task_submission"):
        send_and_track(m.chat.id, "⚠️ You're submitting tasks too quickly. Please wait a moment.", reply_markup=earner_menu(m.chat.id))
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    tasks = load(TASKS_FILE)
    task = tasks.get(task_id, {})
    
    if task.get("status") != "active":
        send_and_track(m.chat.id, "❌ This task is no longer available.", reply_markup=earner_menu(m.chat.id))
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    if user_id in task.get("completed_by", []):
        send_and_track(m.chat.id, "⚠️ You have already completed this task!", reply_markup=earner_menu(m.chat.id))
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    if has_user_submitted_task(user_id, task_id):
        send_and_track(m.chat.id, "⚠️ You have already submitted this task! Please wait for admin approval.", reply_markup=earner_menu(m.chat.id))
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    max_users = task.get("max_users", 1)
    completed_by = task.get("completed_by", [])
    
    if len(completed_by) >= max_users:
        send_and_track(m.chat.id, "❌ This task has reached its user limit.", reply_markup=earner_menu(m.chat.id))
        user_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    submissions = load(SUBMISSIONS_FILE)
    sub_id = f"sub_{user_id}_{task_id}_{int(datetime.now().timestamp())}"
    
    submissions[sub_id] = {
        "user_id": user_id,
        "task_id": task_id,
        "photo_id": m.photo[-1].file_id,
        "status": "pending",
        "submitted": str(datetime.now())
    }
    save(SUBMISSIONS_FILE, submissions)
    
    update_wallet(user_id, "pending_tasks", 1)
    
    users = load(USERS_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    currency = task.get("currency", "naira")
    if currency == "naira":
        reward_text = f"₦{task.get('price_naira', 0)}"
    else:
        reward_text = f"${task.get('price_dollar', 0)}"
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Approve", callback_data=f"approve_{sub_id}"),
        types.InlineKeyboardButton("❌ Reject", callback_data=f"reject_{sub_id}")
    )
    
    bot.send_photo(
        ADMIN_ID,
        m.photo[-1].file_id,
        caption=f"📥 **NEW TASK SUBMISSION**\n\n"
                f"👤 User: {user_name}\n"
                f"🆔 User ID: `{user_id}`\n"
                f"📋 Task ID: `{task_id}`\n"
                f"🌐 Platform: {task.get('platform', 'N/A').title()}\n"
                f"📝 Type: {task.get('task_type', 'N/A').replace('_', ' ').title()}\n"
                f"🔗 Link: {task.get('link', 'N/A')}\n"
                f"💰 Reward: {reward_text}\n"
                f"👥 Completed: {len(completed_by)}/{max_users}",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    
    send_and_track(
        m.chat.id,
        "✅ **TASK SUBMITTED SUCCESSFULLY!**\n\n"
        "⏳ Your submission is under review.\n\n"
        "Waiting for our agents approval...\n\n"
        "⚠️ **IMPORTANT:** You cannot submit this task again until the admin processes your current submission.\n\n"
        "You will be notified once your task is reviewed. 📲",
        reply_markup=earner_menu(m.chat.id),
        parse_mode="Markdown"
    )
    
    user_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data.startswith(("approve_", "reject_")))
def handle_task_decision(c):
    action, sub_id = c.data.split("_", 1)
    
    submissions = load(SUBMISSIONS_FILE)
    if sub_id not in submissions:
        bot.answer_callback_query(c.id, "❌ Task submission not found!")
        return
    
    submission = submissions[sub_id]
    
    if submission["status"] != "pending":
        bot.answer_callback_query(c.id, "⚠️ Already processed!")
        return
    
    user_id = submission["user_id"]
    task_id = submission["task_id"]
    tasks = load(TASKS_FILE)
    
    if task_id not in tasks:
        bot.answer_callback_query(c.id, "❌ Task not found!")
        return
    
    task = tasks[task_id]
    users = load(USERS_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    currency = task.get("currency", "naira")
    if currency == "naira":
        amount = task.get("price_naira", 0)
        reward_text = f"₦{amount}"
    else:
        amount = task.get("price_dollar", 0)
        reward_text = f"${amount}"
    
    if action == "approve":
        if user_id in task.get("completed_by", []):
            bot.answer_callback_query(c.id, "⚠️ User already completed this task!")
            return
        
        submission["status"] = "approved"
        submission["approved_at"] = str(datetime.now())
        
        update_wallet(user_id, "pending_tasks", -1)
        update_wallet(user_id, "completed_tasks", 1)
        
        if currency == "naira":
            update_wallet(user_id, "naira", amount)
        else:
            update_wallet(user_id, "dollar", amount)
        
        if "completed_by" not in tasks[task_id]:
            tasks[task_id]["completed_by"] = []
        
        tasks[task_id]["completed_by"].append(user_id)
        
        max_users = task.get("max_users", 1)
        completed_count = len(tasks[task_id]["completed_by"])
        
        if completed_count >= max_users:
            del tasks[task_id]
            save(TASKS_FILE, tasks)
        else:
            save(TASKS_FILE, tasks)
        
        referrals = load(REFERRALS_FILE)
        for ref_id, ref_list in referrals.items():
            for ref in ref_list:
                if ref["user_id"] == user_id and not ref["reward_paid"]:
                    ref["tasks_completed"] += 1
                    if ref["tasks_completed"] >= 10:
                        ref["reward_paid"] = True
                        update_wallet(ref_id, "naira", 30)
                        update_wallet(ref_id, "referral_naira", 30)
                        update_wallet(ref_id, "referral_count", 1)
                        
                        bot.send_message(
                            ref_id,
                            f"🎊 **REFERRAL REWARD!**\n\n"
                            f"Your referral **{ref['name']}** has completed 10 tasks!\n\n"
                            f"💰 You earned: ₦30\n\n"
                            f"Keep inviting friends to earn more! 🚀",
                            parse_mode="Markdown"
                        )
                    save(REFERRALS_FILE, referrals)
                    break
        
        bot.send_message(
            user_id,
            f"🎉 **TASK APPROVED!**\n\n"
            f"✅ Your task has been approved successfully!\n\n"
            f"📋 Task ID: `{task_id}`\n"
            f"🌐 Platform: {task.get('platform', 'N/A').title()}\n"
            f"📝 Type: {task.get('task_type', 'N/A').replace('_', ' ').title()}\n"
            f"💰 Reward: {reward_text}\n\n"
            f"💵 Money has been added to your balance automatically!\n\n"
            f"Check your balance to see the update! 💰",
            parse_mode="Markdown"
        )
        
        try:
            bot.edit_message_caption(
                f"✅ **APPROVED BY ADMIN**\n\n"
                f"👤 User: {user_name}\n"
                f"🆔 User ID: `{user_id}`\n"
                f"📋 Task ID: `{task_id}`\n"
                f"🌐 Platform: {task.get('platform', 'N/A').title()}\n"
                f"📝 Type: {task.get('task_type', 'N/A').replace('_', ' ').title()}\n"
                f"🔗 Link: {task.get('link', 'N/A')}\n"
                f"💰 Reward: {reward_text}\n"
                f"✅ Approved at: {str(datetime.now())[:16]}",
                c.message.chat.id,
                c.message.message_id,
                parse_mode="Markdown"
            )
        except:
            pass
    
    else:
        submission["status"] = "rejected"
        submission["rejected_at"] = str(datetime.now())
        
        update_wallet(user_id, "pending_tasks", -1)
        
        bot.send_message(
            user_id,
            f"❌ **TASK REJECTED**\n\n"
            f"Sorry, your task submission was rejected.\n\n"
            f"📋 Task ID: `{task_id}`\n"
            f"🌐 Platform: {task.get('platform', 'N/A').title()}\n"
            f"📝 Type: {task.get('task_type', 'N/A').replace('_', ' ').title()}\n"
            f"💰 Reward: {reward_text}\n\n"
            f"You can try submitting this task again if you believe this was an error, "
            f"or contact support for clarification.",
            parse_mode="Markdown"
        )
        
        try:
            bot.edit_message_caption(
                f"❌ **REJECTED BY ADMIN**\n\n"
                f"👤 User: {user_name}\n"
                f"🆔 User ID: `{user_id}`\n"
                f"📋 Task ID: `{task_id}`\n"
                f"🌐 Platform: {task.get('platform', 'N/A').title()}\n"
                f"📝 Type: {task.get('task_type', 'N/A').replace('_', ' ').title()}\n"
                f"🔗 Link: {task.get('link', 'N/A')}\n"
                f"💰 Reward: {reward_text}\n"
                f"❌ Rejected at: {str(datetime.now())[:16]}",
                c.message.chat.id,
                c.message.message_id,
                parse_mode="Markdown"
            )
        except:
            pass
    
    submissions[sub_id] = submission
    save(SUBMISSIONS_FILE, submissions)
    bot.answer_callback_query(c.id, f"✅ Task {action}d successfully!")

@bot.message_handler(func=lambda m: m.text == "💰 My Balance")
def show_balance(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    w = get_wallet(m.chat.id)
    
    if not w:
        send_and_track(m.chat.id, "❌ Error loading wallet.", reply_markup=back_button())
        return
    
    text = (
        f"💳 **YOUR WALLET**\n\n"
        f"✅ Completed: {w['completed_tasks']}\n"
        f"⏳ Pending: {w['pending_tasks']}\n\n"
        f"💵 Naira Balance: ₦{w['naira']:.2f}\n"
        f"💵 USDT Balance: ${w['dollar']:.2f}\n\n"
        f"Select withdrawal option:"
    )
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("💸 Withdraw Naira", callback_data="withdraw_naira"),
        types.InlineKeyboardButton("💸 Withdraw USDT", callback_data="withdraw_usdt")
    )
    
    msg = bot.send_message(m.chat.id, text, reply_markup=kb, parse_mode="Markdown")
    last_message[m.chat.id] = msg.message_id

@bot.callback_query_handler(func=lambda c: c.data.startswith("withdraw_"))
def initiate_withdrawal(c):
    currency = "naira" if "naira" in c.data else "usdt"
    user_state[c.message.chat.id] = f"withdraw_{currency}"
    
    min_amount = "₦1000 (Fee: ₦100)" if currency == "naira" else "$1 (Fee: $0.10)"
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    bot.send_message(
        c.message.chat.id,
        f"💰 Enter withdrawal amount:\n\n"
        f"Minimum: {min_amount}",
        reply_markup=kb
    )

@bot.message_handler(func=lambda m: user_state.get(m.chat.id, "").startswith("withdraw_"))
def process_withdrawal(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_state.pop(m.chat.id, None)
        return show_balance(m)
    
    if not validate_amount(m.text):
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a positive number:", reply_markup=back_button())
        return
    
    currency = user_state[m.chat.id].split("_")[1]
    
    try:
        amount = float(m.text)
    except:
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a number:", reply_markup=back_button())
        return
    
    w = get_wallet(m.chat.id)
    
    if not w:
        send_and_track(m.chat.id, "❌ Error loading wallet.", reply_markup=back_button())
        return
    
    if currency == "naira":
        min_amount = 1000
        fee = 100
        balance_key = "naira"
        symbol = "₦"
    else:
        min_amount = 1
        fee = 0.10
        balance_key = "dollar"
        symbol = "$"
    
    if amount < min_amount:
        send_and_track(m.chat.id, f"❌ Minimum withdrawal is {symbol}{min_amount}!", reply_markup=back_button())
        return
    
    total = amount + fee
    
    if total > w[balance_key]:
        send_and_track(
            m.chat.id,
            f"❌ Insufficient balance!\n\n"
            f"Required: {symbol}{total:.2f} (Amount + Fee)\n"
            f"Your balance: {symbol}{w[balance_key]:.2f}",
            reply_markup=back_button()
        )
        return
    
    bank_data = load(BANK_FILE)
    user_id = str(m.chat.id)
    
    if user_id not in bank_data:
        send_and_track(
            m.chat.id,
            "⚠️ No payment details found!\n\n"
            "Please add your payment details first by clicking '💳 Payment Details' button.",
            reply_markup=earner_menu(m.chat.id)
        )
        user_state.pop(m.chat.id, None)
        return
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Confirm", callback_data=f"confirm_withdraw_{currency}_{amount}"),
        types.InlineKeyboardButton("🔄 Change Details", callback_data="change_payment_details")
    )
    
    bank_info = bank_data[user_id]
    msg = bot.send_message(
        m.chat.id,
        f"📋 **WITHDRAWAL SUMMARY**\n\n"
        f"💰 Amount: {symbol}{amount:.2f}\n"
        f"💳 Fee: {symbol}{fee:.2f}\n"
        f"📊 Total: {symbol}{total:.2f}\n\n"
        f"💳 **Payment Details:**\n"
        f"Type: {bank_info['type']}\n\n"
        f"Details:\n{bank_info['details']}\n\n"
        f"Confirm withdrawal?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id
    user_state.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "change_payment_details")
def change_payment_details(c):
    bot.edit_message_text(
        "Please go to main menu and click '💳 Payment Details' to update your payment information.",
        c.message.chat.id,
        c.message.message_id
    )

@bot.callback_query_handler(func=lambda c: c.data.startswith("confirm_withdraw_"))
def confirm_withdrawal(c):
    parts = c.data.split("_")
    currency = parts[2]
    
    try:
        amount = float(parts[3])
        if not validate_amount(amount):
            bot.answer_callback_query(c.id, "❌ Invalid amount!")
            return
    except:
        bot.answer_callback_query(c.id, "❌ Invalid amount!")
        return
    
    user_id = str(c.message.chat.id)
    
    if currency == "naira":
        fee = 100
        balance_key = "naira"
        symbol = "₦"
    else:
        fee = 0.10
        balance_key = "dollar"
        symbol = "$"
    
    total = amount + fee
    
    wallet = get_wallet(user_id)
    
    if not wallet:
        bot.answer_callback_query(c.id, "❌ Error loading wallet!")
        return
    
    if wallet[balance_key] < total:
        bot.answer_callback_query(c.id, "❌ Insufficient balance!")
        bot.edit_message_text(
            f"❌ **INSUFFICIENT BALANCE**\n\n"
            f"You need: {symbol}{total:.2f}\n"
            f"Your balance: {symbol}{wallet[balance_key]:.2f}",
            c.message.chat.id,
            c.message.message_id,
            parse_mode="Markdown"
        )
        return
    
    update_wallet(user_id, balance_key, -total)
    
    withdrawals = load(WITHDRAWALS_FILE)
    withdrawal_id = f"wd_{user_id}_{int(datetime.now().timestamp())}"
    
    withdrawals[withdrawal_id] = {
        "user_id": user_id,
        "currency": currency,
        "amount": amount,
        "fee": fee,
        "total": total,
        "status": "pending",
        "requested": str(datetime.now())
    }
    save(WITHDRAWALS_FILE, withdrawals)
    
    users = load(USERS_FILE)
    bank_data = load(BANK_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Approve", callback_data=f"approve_wd_{withdrawal_id}"),
        types.InlineKeyboardButton("❌ Cancel", callback_data=f"cancel_wd_{withdrawal_id}")
    )
    
    bot.send_message(
        ADMIN_ID,
        f"💸 **WITHDRAWAL REQUEST**\n\n"
        f"👤 User: {user_name}\n"
        f"🆔 ID: `{user_id}`\n"
        f"💰 Amount: {symbol}{amount:.2f}\n"
        f"💳 Fee: {symbol}{fee:.2f}\n"
        f"📊 Total: {symbol}{total:.2f}\n\n"
        f"💳 Payment Type: {bank_data[user_id]['type']}\n\n"
        f"📝 Payment Details:\n{bank_data[user_id]['details']}\n\n"
        f"⚠️ **Note:** Money already deducted from user's bot wallet!",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    
    bot.edit_message_text(
        f"✅ **WITHDRAWAL REQUEST SUBMITTED!**\n\n"
        f"💰 Amount: {symbol}{amount:.2f}\n"
        f"💳 Fee: {symbol}{fee:.2f}\n"
        f"📊 Total Deducted: {symbol}{total:.2f}\n\n"
        f"💵 **Money has been deducted from your bot balance.**\n\n"
        f"⏰ Please wait a few minutes while admin processes your payment.\n\n"
        f"You will receive a notification when the money reaches your bank account/wallet.\n\n"
        f"Thank you for your patience! 🙏",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )

@bot.message_handler(func=lambda m: m.text == "💸 Withdrawal Requests" and m.chat.id == ADMIN_ID)
def view_withdrawal_requests(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    withdrawals = load(WITHDRAWALS_FILE)
    users = load(USERS_FILE)
    bank_data = load(BANK_FILE)
    
    pending = []
    approved = []
    cancelled = []
    
    for wd_id, wd_data in withdrawals.items():
        if wd_data["status"] == "pending":
            pending.append((wd_id, wd_data))
        elif wd_data["status"] == "approved":
            approved.append((wd_id, wd_data))
        else:
            cancelled.append((wd_id, wd_data))
    
    text = f"💸 **WITHDRAWAL REQUESTS**\n\n"
    text += f"⏳ Pending: {len(pending)}\n"
    text += f"✅ Approved: {len(approved)}\n"
    text += f"❌ Cancelled: {len(cancelled)}\n\n"
    
    if pending:
        text += "━━━━━━━━━━━━━━━━━━\n\n"
        text += "⏳ **PENDING REQUESTS:**\n\n"
        for wd_id, wd_data in pending[:5]:
            user_name = users.get(wd_data["user_id"], {}).get("name", "Unknown")
            bank_info = bank_data.get(wd_data["user_id"], {})
            
            symbol = "₦" if wd_data["currency"] == "naira" else "$"
            
            text += f"👤 {user_name}\n"
            text += f"🆔 `{wd_data['user_id']}`\n"
            text += f"💰 Amount: {symbol}{wd_data['amount']:.2f}\n"
            text += f"💳 Fee: {symbol}{wd_data['fee']:.2f}\n"
            text += f"📊 Total: {symbol}{wd_data['total']:.2f}\n"
            text += f"💳 Type: {bank_info.get('type', 'N/A')}\n"
            text += f"📅 {wd_data['requested'][:16]}\n"
            text += f"ID: `{wd_id}`\n\n"
    else:
        text += "\n✅ No pending withdrawal requests!"
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

@bot.callback_query_handler(func=lambda c: c.data.startswith("approve_wd_"))
def process_withdrawal_approval(c):
    withdrawal_id = c.data.replace("approve_wd_", "")
    
    withdrawals = load(WITHDRAWALS_FILE)
    
    if withdrawal_id not in withdrawals:
        bot.answer_callback_query(c.id, "❌ Withdrawal request not found!")
        return
    
    withdrawal = withdrawals[withdrawal_id]
    
    if withdrawal["status"] != "pending":
        bot.answer_callback_query(c.id, "⚠️ Already processed!")
        return
    
    user_id = withdrawal["user_id"]
    total = withdrawal["total"]
    currency = withdrawal["currency"]
    amount = withdrawal["amount"]
    fee = withdrawal["fee"]
    
    if currency == "naira":
        symbol = "₦"
    else:
        symbol = "$"
    
    withdrawal["status"] = "approved"
    withdrawal["approved_at"] = str(datetime.now())
    withdrawals[withdrawal_id] = withdrawal
    save(WITHDRAWALS_FILE, withdrawals)
    
    bot.send_message(
        user_id,
        f"✅ **PAYMENT SENT!**\n\n"
        f"Your withdrawal has been processed successfully! 🎉\n\n"
        f"💰 Amount: {symbol}{amount:.2f}\n"
        f"💳 Fee: {symbol}{fee:.2f}\n"
        f"📊 Total: {symbol}{total:.2f}\n\n"
        f"💵 The money has been sent to your bank account/wallet.\n\n"
        f"Please check your account to confirm the payment.\n\n"
        f"If you don't see the payment within 24 hours, please contact support.\n\n"
        f"Thank you for using SOCIAL MEDIA EARNING! 🙏",
        parse_mode="Markdown"
    )
    
    try:
        bot.edit_message_text(
            f"✅ **PAYMENT SENT**\n\n{c.message.text}\n\n✅ Approved at: {str(datetime.now())[:16]}",
            c.message.chat.id,
            c.message.message_id,
            parse_mode="Markdown"
        )
    except:
        pass
    
    bot.answer_callback_query(c.id, "✅ Withdrawal approved!")

@bot.callback_query_handler(func=lambda c: c.data.startswith("cancel_wd_"))
def process_withdrawal_cancellation(c):
    withdrawal_id = c.data.replace("cancel_wd_", "")
    
    withdrawals = load(WITHDRAWALS_FILE)
    
    if withdrawal_id not in withdrawals:
        bot.answer_callback_query(c.id, "❌ Withdrawal request not found!")
        return
    
    withdrawal = withdrawals[withdrawal_id]
    
    if withdrawal["status"] != "pending":
        bot.answer_callback_query(c.id, "⚠️ Already processed!")
        return
    
    user_id = withdrawal["user_id"]
    total = withdrawal["total"]
    currency = withdrawal["currency"]
    
    if currency == "naira":
        update_wallet(user_id, "naira", total)
        symbol = "₦"
    else:
        update_wallet(user_id, "dollar", total)
        symbol = "$"
    
    withdrawal["status"] = "cancelled"
    withdrawal["cancelled_at"] = str(datetime.now())
    withdrawals[withdrawal_id] = withdrawal
    save(WITHDRAWALS_FILE, withdrawals)
    
    bot.send_message(
        user_id,
        f"❌ **WITHDRAWAL CANCELLED**\n\n"
        f"Your withdrawal request was cancelled by admin.\n\n"
        f"💰 {symbol}{total:.2f} has been returned to your wallet.\n\n"
        f"Please contact support for more information.",
        parse_mode="Markdown"
    )
    
    try:
        bot.edit_message_text(
            f"❌ **CANCELLED**\n\n{c.message.text}\n\n❌ Cancelled at: {str(datetime.now())[:16]}\n💰 Money returned to user wallet",
            c.message.chat.id,
            c.message.message_id,
            parse_mode="Markdown"
        )
    except:
        pass
    
    bot.answer_callback_query(c.id, "✅ Withdrawal cancelled and money returned!")

@bot.message_handler(func=lambda m: m.text == "✏️ Edit Withdrawal Status" and m.chat.id == ADMIN_ID)
def edit_withdrawal_status_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(
        m.chat.id, 
        "🆔 **EDIT WITHDRAWAL STATUS**\n\n"
        "Enter Withdrawal ID to edit:\n\n"
        "💡 Tip: You can find withdrawal IDs in '💸 Withdrawal Requests' menu",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[m.chat.id] = "edit_withdrawal_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "edit_withdrawal_id" and m.chat.id == ADMIN_ID)
def edit_withdrawal_id(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    withdrawal_id = m.text.strip()
    withdrawals = load(WITHDRAWALS_FILE)
    
    if withdrawal_id not in withdrawals:
        send_and_track(m.chat.id, "❌ Withdrawal ID not found! Try again:", reply_markup=back_button())
        return
    
    withdrawal = withdrawals[withdrawal_id]
    users = load(USERS_FILE)
    bank_data = load(BANK_FILE)
    
    user_id = withdrawal["user_id"]
    user_name = users.get(user_id, {}).get("name", "Unknown")
    bank_info = bank_data.get(user_id, {})
    
    symbol = "₦" if withdrawal["currency"] == "naira" else "$"
    status_emoji = "✅" if withdrawal["status"] == "approved" else "⏳" if withdrawal["status"] == "pending" else "❌"
    
    text = (
        f"💸 **WITHDRAWAL DETAILS**\n\n"
        f"ID: `{withdrawal_id}`\n\n"
        f"👤 User: {user_name}\n"
        f"🆔 User ID: `{user_id}`\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💰 Amount: {symbol}{withdrawal['amount']:.2f}\n"
        f"💳 Fee: {symbol}{withdrawal['fee']:.2f}\n"
        f"📊 Total: {symbol}{withdrawal['total']:.2f}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📋 Status: {status_emoji} {withdrawal['status'].upper()}\n"
        f"📅 Requested: {withdrawal['requested'][:16]}\n\n"
    )
    
    if withdrawal['status'] == 'approved' and 'approved_at' in withdrawal:
        text += f"✅ Approved: {withdrawal['approved_at'][:16]}\n\n"
    elif withdrawal['status'] == 'cancelled' and 'cancelled_at' in withdrawal:
        text += f"❌ Cancelled: {withdrawal['cancelled_at'][:16]}\n\n"
    
    text += (
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💳 Payment Type: {bank_info.get('type', 'N/A')}\n\n"
        f"📝 Details:\n{bank_info.get('details', 'Not set')}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Change status to:"
    )
    
    temp_data[m.chat.id] = {"editing_withdrawal": withdrawal_id}
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    
    if withdrawal['status'] == 'pending':
        kb.row("✅ Mark as Completed")
        kb.row("❌ Mark as Cancelled")
    elif withdrawal['status'] == 'approved':
        kb.row("⏳ Mark as Pending")
        kb.row("❌ Mark as Cancelled")
    elif withdrawal['status'] == 'cancelled':
        kb.row("⏳ Mark as Pending")
        kb.row("✅ Mark as Completed")
    
    kb.row("🔙 Back")
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=kb)
    admin_state[m.chat.id] = "edit_withdrawal_action"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "edit_withdrawal_action" and m.chat.id == ADMIN_ID)
def edit_withdrawal_action(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "edit_withdrawal_id"
        temp_data.pop(m.chat.id, None)
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(
            m.chat.id, 
            "🆔 **EDIT WITHDRAWAL STATUS**\n\n"
            "Enter Withdrawal ID to edit:\n\n"
            "💡 Tip: You can find withdrawal IDs in '💸 Withdrawal Requests' menu",
            reply_markup=kb,
            parse_mode="Markdown"
        )
    
    withdrawal_id = temp_data[m.chat.id]["editing_withdrawal"]
    withdrawals = load(WITHDRAWALS_FILE)
    withdrawal = withdrawals[withdrawal_id]
    
    users = load(USERS_FILE)
    user_id = withdrawal["user_id"]
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    old_status = withdrawal["status"]
    new_status = None
    
    if "Completed" in m.text:
        new_status = "approved"
        withdrawal["approved_at"] = str(datetime.now())
        withdrawal.pop("cancelled_at", None)
    elif "Cancelled" in m.text:
        new_status = "cancelled"
        withdrawal["cancelled_at"] = str(datetime.now())
        withdrawal.pop("approved_at", None)
    elif "Pending" in m.text:
        new_status = "pending"
        withdrawal.pop("approved_at", None)
        withdrawal.pop("cancelled_at", None)
    
    if new_status is None:
        send_and_track(m.chat.id, "❌ Invalid action!", reply_markup=admin_menu())
        admin_state.pop(m.chat.id, None)
        temp_data.pop(m.chat.id, None)
        return
    
    total = withdrawal["total"]
    currency = withdrawal["currency"]
    symbol = "₦" if currency == "naira" else "$"
    balance_key = "naira" if currency == "naira" else "dollar"
    
    if old_status == "pending" and new_status == "cancelled":
        update_wallet(user_id, balance_key, total)
    elif old_status == "cancelled" and new_status == "pending":
        wallet = get_wallet(user_id)
        if wallet[balance_key] < total:
            send_and_track(
                m.chat.id,
                f"❌ **CANNOT CHANGE STATUS**\n\n"
                f"User doesn't have enough balance.\n\n"
                f"Required: {symbol}{total:.2f}\n"
                f"User has: {symbol}{wallet[balance_key]:.2f}",
                reply_markup=admin_menu(),
                parse_mode="Markdown"
            )
            admin_state.pop(m.chat.id, None)
            temp_data.pop(m.chat.id, None)
            return
        update_wallet(user_id, balance_key, -total)
    elif old_status == "approved" and new_status == "cancelled":
        update_wallet(user_id, balance_key, total)
    elif old_status == "cancelled" and new_status == "approved":
        wallet = get_wallet(user_id)
        if wallet[balance_key] < total:
            send_and_track(
                m.chat.id,
                f"❌ **CANNOT CHANGE STATUS**\n\n"
                f"User doesn't have enough balance.\n\n"
                f"Required: {symbol}{total:.2f}\n"
                f"User has: {symbol}{wallet[balance_key]:.2f}",
                reply_markup=admin_menu(),
                parse_mode="Markdown"
            )
            admin_state.pop(m.chat.id, None)
            temp_data.pop(m.chat.id, None)
            return
        update_wallet(user_id, balance_key, -total)
    elif old_status == "approved" and new_status == "pending":
        update_wallet(user_id, balance_key, total)
    
    withdrawal["status"] = new_status
    withdrawals[withdrawal_id] = withdrawal
    save(WITHDRAWALS_FILE, withdrawals)
    
    send_and_track(
        m.chat.id,
        f"✅ **STATUS UPDATED SUCCESSFULLY**\n\n"
        f"👤 User: {user_name}\n"
        f"🆔 ID: `{user_id}`\n"
        f"💸 Withdrawal ID: `{withdrawal_id}`\n\n"
        f"Old Status: {old_status.upper()}\n"
        f"New Status: {new_status.upper()}\n\n"
        f"💰 Amount: {symbol}{withdrawal['amount']:.2f}\n"
        f"📊 Total: {symbol}{total:.2f}\n\n"
        f"⚠️ User was NOT notified about this change.",
        reply_markup=admin_menu(),
        parse_mode="Markdown"
    )
    
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

@bot.message_handler(func=lambda m: m.text == "👥 My Referrals")
def show_referrals(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    user_id = str(m.chat.id)
    referrals = load(REFERRALS_FILE)
    w = get_wallet(user_id)
    
    if not w:
        send_and_track(m.chat.id, "❌ Error loading wallet.", reply_markup=back_button())
        return
    
    ref_link = f"{BOT_LINK}?start={user_id}"
    
    ref_list = referrals.get(user_id, [])
    
    text = (
        f"👥 **YOUR REFERRALS**\n\n"
        f"🔗 **Referral Link:**\n`{ref_link}`\n\n"
        f"📊 **Statistics:**\n"
        f"👤 Total Referrals: {w['referral_count']}\n"
        f"💰 Earned (Naira): ₦{w['referral_naira']:.2f}\n"
        f"💵 Earned (USDT): ${w['referral_dollar']:.2f}\n\n"
    )
    
    if ref_list:
        text += "📋 **Referral List:**\n\n"
        for ref in ref_list:
            status = "✅ Paid" if ref["reward_paid"] else f"⏳ {ref['tasks_completed']}/10 tasks"
            text += f"• {ref['name']} - {status}\n"
    else:
        text += "😔 No referrals yet. Start inviting friends!"
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

@bot.message_handler(func=lambda m: m.text == "➕ Create Task" and m.chat.id == ADMIN_ID)
def create_task_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("TikTok", "Facebook")
    kb.row("Instagram", "Twitter")
    kb.row("🔙 Back")
    send_and_track(m.chat.id, "📱 Select social media platform:", reply_markup=kb)
    admin_state[m.chat.id] = "task_platform"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "task_platform" and m.chat.id == ADMIN_ID)
def task_platform(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    platform = m.text.lower()
    temp_data[m.chat.id] = {"platform": platform}
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("Like", "Comment", "Share")
    kb.row("Follow", "Join Group", "Join Channel")
    kb.row("🔙 Back")
    send_and_track(m.chat.id, "📝 Select task type:", reply_markup=kb)
    admin_state[m.chat.id] = "task_type"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "task_type" and m.chat.id == ADMIN_ID)
def task_type(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "task_platform"
        return create_task_start(m)
    
    task_type = m.text.lower().replace(" ", "_")
    temp_data[m.chat.id]["task_type"] = task_type
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "🔗 Send the link for the task:", reply_markup=kb)
    admin_state[m.chat.id] = "task_link"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "task_link" and m.chat.id == ADMIN_ID)
def task_link(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "task_type"
        temp_data_copy = temp_data.get(m.chat.id, {})
        
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("Like", "Comment", "Share")
        kb.row("Follow", "Join Group", "Join Channel")
        kb.row("🔙 Back")
        return send_and_track(m.chat.id, "📝 Select task type:", reply_markup=kb)
    
    temp_data[m.chat.id]["link"] = m.text[:500]
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("Naira (₦)", "Dollar ($)")
    kb.row("🔙 Back")
    send_and_track(m.chat.id, "💵 Select currency:", reply_markup=kb)
    admin_state[m.chat.id] = "task_currency"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "task_currency" and m.chat.id == ADMIN_ID)
def task_currency(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "task_link"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(m.chat.id, "🔗 Send the link for the task:", reply_markup=kb)
    
    currency = "naira" if "Naira" in m.text else "dollar"
    temp_data[m.chat.id]["currency"] = currency
    
    symbol = "₦" if currency == "naira" else "$"
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, f"💰 Enter price per task ({symbol}):", reply_markup=kb)
    admin_state[m.chat.id] = "task_price"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "task_price" and m.chat.id == ADMIN_ID)
def task_price(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "task_currency"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("Naira (₦)", "Dollar ($)")
        kb.row("🔙 Back")
        return send_and_track(m.chat.id, "💵 Select currency:", reply_markup=kb)
    
    if not validate_amount(m.text):
        send_and_track(m.chat.id, "❌ Invalid price! Enter a positive number:", reply_markup=back_button())
        return
    
    try:
        price = float(m.text)
    except:
        send_and_track(m.chat.id, "❌ Invalid price! Enter a number:", reply_markup=back_button())
        return
    
    temp_data[m.chat.id]["price"] = price
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(
        m.chat.id, 
        "🔢 **HOW MANY UNIQUE USERS?**\n\n"
        "Enter the number of DIFFERENT users who should complete this task.\n\n"
        "⚠️ Example: If you enter 40, the task will be available for 40 DIFFERENT users, and each user can complete it only ONCE.",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[m.chat.id] = "task_quantity"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "task_quantity" and m.chat.id == ADMIN_ID)
def task_quantity(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "task_price"
        currency = temp_data[m.chat.id]["currency"]
        symbol = "₦" if currency == "naira" else "$"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(m.chat.id, f"💰 Enter price per task ({symbol}):", reply_markup=kb)
    
    try:
        max_users = int(m.text)
        if max_users <= 0:
            send_and_track(m.chat.id, "❌ Number must be positive!", reply_markup=back_button())
            return
        if max_users > 10000:
            send_and_track(m.chat.id, "❌ Maximum 10,000 users allowed!", reply_markup=back_button())
            return
    except:
        send_and_track(m.chat.id, "❌ Invalid number! Enter a whole number:", reply_markup=back_button())
        return
    
    task_data = temp_data[m.chat.id]
    price = task_data["price"]
    currency = task_data["currency"]
    total_cost = price * max_users
    symbol = "₦" if currency == "naira" else "$"
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Confirm", callback_data=f"confirm_task_{max_users}"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_task")
    )
    
    summary = (
        f"📋 **TASK CREATION SUMMARY**\n\n"
        f"🌐 Platform: {task_data['platform'].title()}\n"
        f"📝 Type: {task_data['task_type'].replace('_', ' ').title()}\n"
        f"🔗 Link: {task_data['link']}\n"
        f"💰 Price per task: {symbol}{price:.2f}\n"
        f"👥 Max Users: {max_users} unique users\n"
        f"📊 Total Budget: {symbol}{total_cost:.2f}\n\n"
        f"⚠️ **IMPORTANT:**\n"
        f"• This task will be available for {max_users} DIFFERENT users\n"
        f"• Each user can complete it only ONCE\n"
        f"• Task auto-deletes after {max_users} unique completions\n\n"
        f"Confirm task creation?"
    )
    
    msg = bot.send_message(m.chat.id, summary, reply_markup=kb, parse_mode="Markdown")
    last_message[m.chat.id] = msg.message_id

@bot.callback_query_handler(func=lambda c: c.data.startswith("confirm_task_"))
def confirm_task(c):
    try:
        max_users = int(c.data.split("_")[2])
    except:
        bot.answer_callback_query(c.id, "❌ Invalid data!")
        return
    
    task_data = temp_data.get(c.message.chat.id)
    
    if not task_data:
        bot.answer_callback_query(c.id, "❌ Session expired!")
        return
    
    price = task_data["price"]
    currency = task_data["currency"]
    
    tasks = load(TASKS_FILE)
    
    task_id = f"task_{c.message.chat.id}_{int(datetime.now().timestamp())}"
    tasks[task_id] = {
        "platform": task_data["platform"],
        "task_type": task_data["task_type"],
        "link": task_data["link"],
        "currency": currency,
        f"price_{currency}": price,
        "status": "active",
        "completed_by": [],
        "max_users": max_users,
        "created": str(datetime.now()),
        "created_by": "admin"
    }
    
    save(TASKS_FILE, tasks)
    
    bot.edit_message_text(
        f"✅ **TASK CREATED SUCCESSFULLY!**\n\n"
        f"🎯 Task ID: `{task_id}`\n"
        f"👥 Available for: {max_users} unique users\n"
        f"💰 Reward per user: {('₦' if currency == 'naira' else '$')}{price:.2f}\n\n"
        f"The task is now active and will:\n"
        f"• Be visible to users who haven't completed it\n"
        f"• Block duplicate attempts by the same user\n"
        f"• Auto-delete after {max_users} unique completions\n\n"
        f"Users can now start completing this task! 🚀",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )
    
    admin_state.pop(c.message.chat.id, None)
    temp_data.pop(c.message.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "cancel_task")
def cancel_task(c):
    bot.edit_message_text(
        "❌ Task creation cancelled.",
        c.message.chat.id,
        c.message.message_id
    )
    admin_state.pop(c.message.chat.id, None)
    temp_data.pop(c.message.chat.id, None)

@bot.message_handler(func=lambda m: m.text == "🗑️ Delete Task" and m.chat.id == ADMIN_ID)
def delete_task_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(
        m.chat.id,
        "🆔 **DELETE TASK**\n\n"
        "Enter Task ID to delete:\n\n"
        "💡 Tip: You can find task IDs by viewing available tasks as a user",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[m.chat.id] = "delete_task_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "delete_task_id" and m.chat.id == ADMIN_ID)
def delete_task_confirm(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    task_id = m.text.strip()
    tasks = load(TASKS_FILE)
    
    if task_id not in tasks:
        send_and_track(m.chat.id, "❌ Task ID not found! Try again:", reply_markup=back_button())
        return
    
    task = tasks[task_id]
    
    symbol = "₦" if task.get("currency") == "naira" else "$"
    price_key = f"price_{task.get('currency', 'naira')}"
    completed_by = task.get("completed_by", [])
    max_users = task.get("max_users", 1)
    
    text = (
        f"🗑️ **CONFIRM TASK DELETION**\n\n"
        f"Task ID: `{task_id}`\n"
        f"Platform: {task.get('platform', 'N/A').title()}\n"
        f"Type: {task.get('task_type', 'N/A').replace('_', ' ').title()}\n"
        f"Link: {task.get('link', 'N/A')}\n"
        f"Reward: {symbol}{task.get(price_key, 0):.2f}\n"
        f"Status: {task.get('status', 'N/A').upper()}\n"
        f"Completed: {len(completed_by)}/{max_users} users\n\n"
        f"⚠️ **WARNING:**\n"
        f"• This will permanently delete the task\n"
        f"• Users won't be able to complete it anymore\n"
        f"• This action cannot be undone\n\n"
        f"Are you sure you want to delete this task?"
    )
    
    temp_data[m.chat.id] = {"deleting_task": task_id}
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Yes, Delete", callback_data=f"confirm_delete_task"),
        types.InlineKeyboardButton("❌ No, Cancel", callback_data="cancel_delete_task")
    )
    
    msg = bot.send_message(m.chat.id, text, reply_markup=kb, parse_mode="Markdown")
    last_message[m.chat.id] = msg.message_id
    admin_state.pop(m.chat.id, None)

@bot.callback_query_handler(func=lambda c: c.data == "confirm_delete_task")
def execute_delete_task(c):
    task_id = temp_data.get(c.message.chat.id, {}).get("deleting_task")
    
    if not task_id:
        bot.answer_callback_query(c.id, "❌ Session expired!")
        return
    
    tasks = load(TASKS_FILE)
    
    if task_id not in tasks:
        bot.answer_callback_query(c.id, "❌ Task not found!")
        return
    
    task = tasks[task_id]
    
    platform = task.get('platform', 'N/A').title()
    task_type = task.get('task_type', 'N/A').replace('_', ' ').title()
    link = task.get('link', 'N/A')
    completed_count = len(task.get('completed_by', []))
    max_users = task.get('max_users', 1)
    
    del tasks[task_id]
    save(TASKS_FILE, tasks)
    
    bot.edit_message_text(
        f"✅ **TASK DELETED SUCCESSFULLY!**\n\n"
        f"Task ID: `{task_id}`\n"
        f"Platform: {platform}\n"
        f"Type: {task_type}\n"
        f"Link: {link}\n"
        f"Completed: {completed_count}/{max_users} users\n\n"
        f"The task has been permanently removed from the system.",
        c.message.chat.id,
        c.message.message_id,
        parse_mode="Markdown"
    )
    
    temp_data.pop(c.message.chat.id, None)
    bot.answer_callback_query(c.id, "✅ Task deleted!")

@bot.callback_query_handler(func=lambda c: c.data == "cancel_delete_task")
def cancel_delete_task(c):
    bot.edit_message_text(
        "❌ Task deletion cancelled.\n\n"
        "The task was NOT deleted.",
        c.message.chat.id,
        c.message.message_id
    )
    temp_data.pop(c.message.chat.id, None)
    bot.answer_callback_query(c.id, "Cancelled")

@bot.message_handler(func=lambda m: m.text == "👤 Manage User" and m.chat.id == ADMIN_ID)
def manage_user_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "🆔 Enter User ID to manage:", reply_markup=kb)
    admin_state[m.chat.id] = "manage_user_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "manage_user_id" and m.chat.id == ADMIN_ID)
def manage_user_id(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    if not validate_user_id(m.text):
        send_and_track(m.chat.id, "❌ Invalid User ID! Try again:", reply_markup=back_button())
        return
    
    user_id = str(m.text)
    users = load(USERS_FILE)
    
    if user_id not in users:
        send_and_track(m.chat.id, f"❌ User ID {user_id} not found!", reply_markup=back_button())
        return
    
    temp_data[m.chat.id] = {"managing_user": user_id}
    
    user_data = users[user_id]
    wallet = get_wallet(user_id)
    bank_data = load(BANK_FILE)
    bank_info = bank_data.get(user_id, {})
    withdrawals = load(WITHDRAWALS_FILE)
    
    user_withdrawals = [w for w in withdrawals.values() if w["user_id"] == user_id]
    total_withdrawals = len(user_withdrawals)
    approved_withdrawals = len([w for w in user_withdrawals if w["status"] == "approved"])
    pending_withdrawals = len([w for w in user_withdrawals if w["status"] == "pending"])
    
    text = (
        f"👤 **USER MANAGEMENT**\n\n"
        f"📛 Name: {user_data.get('name', 'Unknown')}\n"
        f"🆔 User ID: `{user_id}`\n"
        f"📅 Joined: {user_data.get('joined', 'N/A')[:16]}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💰 **CURRENT BALANCES:**\n"
        f"₦ Naira: ₦{wallet['naira']:.2f}\n"
        f"💵 USDT: ${wallet['dollar']:.2f}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📊 **TASK STATISTICS:**\n"
        f"✅ Completed Tasks: {wallet['completed_tasks']}\n"
        f"⏳ Pending Tasks: {wallet['pending_tasks']}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💸 **WITHDRAWAL HISTORY:**\n"
        f"📋 Total Withdrawals: {total_withdrawals}\n"
        f"✅ Approved: {approved_withdrawals}\n"
        f"⏳ Pending: {pending_withdrawals}\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💳 **PAYMENT DETAILS:**\n"
    )
    
    if bank_info:
        text += (
            f"Type: {bank_info.get('type', 'N/A')}\n"
            f"Details:\n{bank_info.get('details', 'Not set')}\n"
            f"Updated: {bank_info.get('updated', 'N/A')[:16]}\n\n"
        )
    else:
        text += "⚠️ Not set\n\n"
    
    text += "Select what to edit:"
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("📊 Edit Tasks Count")
    kb.row("💸 View Withdrawals")
    kb.row("💳 Edit Bank Details")
    kb.row("🔙 Back")
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=kb)
    admin_state[m.chat.id] = "manage_user_menu"

@bot.message_handler(func=lambda m: m.text == "💰 Adjust Balance" and m.chat.id == ADMIN_ID)
def adjust_balance_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "🆔 Enter User ID:", reply_markup=kb)
    admin_state[m.chat.id] = "adjust_user_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "adjust_user_id" and m.chat.id == ADMIN_ID)
def adjust_user_id(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    if not validate_user_id(m.text):
        send_and_track(m.chat.id, "❌ Invalid User ID!", reply_markup=back_button())
        return
    
    temp_data[m.chat.id] = {"adjust_user": m.text}
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("➕ Add Naira", "➖ Minus Naira")
    kb.row("➕ Add Dollar", "➖ Minus Dollar")
    kb.row("🔙 Back")
    
    send_and_track(m.chat.id, "💰 Select action:", reply_markup=kb)
    admin_state[m.chat.id] = "adjust_action"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "adjust_action" and m.chat.id == ADMIN_ID)
def adjust_action(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "adjust_user_id"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(m.chat.id, "🆔 Enter User ID:", reply_markup=kb)
    
    temp_data[m.chat.id]["adjust_action"] = m.text
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "💵 Enter amount:", reply_markup=kb)
    admin_state[m.chat.id] = "adjust_amount"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "adjust_amount" and m.chat.id == ADMIN_ID)
def adjust_amount(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "adjust_action"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("➕ Add Naira", "➖ Minus Naira")
        kb.row("➕ Add Dollar", "➖ Minus Dollar")
        kb.row("🔙 Back")
        return send_and_track(m.chat.id, "💰 Select action:", reply_markup=kb)
    
    if not validate_amount(m.text):
        send_and_track(m.chat.id, "❌ Invalid amount! Enter a positive number:", reply_markup=back_button())
        return
    
    try:
        amount = float(m.text)
    except:
        send_and_track(m.chat.id, "❌ Invalid amount!", reply_markup=back_button())
        return
    
    temp_data[m.chat.id]["adjust_amount"] = amount
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "📝 Enter reason:", reply_markup=kb)
    admin_state[m.chat.id] = "adjust_reason"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "adjust_reason" and m.chat.id == ADMIN_ID)
def adjust_reason(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "adjust_amount"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(m.chat.id, "💵 Enter amount:", reply_markup=kb)
    
    data = temp_data[m.chat.id]
    user_id = data["adjust_user"]
    action = data["adjust_action"]
    amount = data["adjust_amount"]
    reason = m.text[:200]
    
    currency = "naira" if "Naira" in action else "dollar"
    multiplier = 1 if "Add" in action else -1
    final_amount = amount * multiplier
    
    update_wallet(user_id, currency, final_amount)
    
    log_transfer_event("balance_adjustment", user_id, None, amount, "success", reason, ADMIN_ID)
    
    symbol = "₦" if currency == "naira" else "$"
    action_text = "added to" if multiplier > 0 else "deducted from"
    
    try:
        bot.send_message(
            user_id,
            f"{'🎊' if multiplier > 0 else '⚠️'} **BALANCE UPDATE**\n\n"
            f"{symbol}{abs(amount):.2f} has been {action_text} your balance.\n\n"
            f"📝 Reason: {reason}",
            parse_mode="Markdown"
        )
    except:
        pass
    
    send_and_track(
        m.chat.id,
        f"✅ Balance adjusted!\n\n"
        f"User: {user_id}\n"
        f"Action: {action}\n"
        f"Amount: {symbol}{amount:.2f}",
        reply_markup=admin_menu()
    )
    
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

@bot.message_handler(func=lambda m: m.text == "💬 Support")
def support(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb_inline = types.InlineKeyboardMarkup()
    kb_inline.add(types.InlineKeyboardButton("💬 Contact Support", url=f"https://t.me/{ADMIN_USERNAME.replace('@', '').replace('https://t.me/', '')}"))
    
    kb_reply = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb_reply.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        f"💬 **SUPPORT**\n\n"
        f"Need help? Contact our support team:\n\n"
        f"👤 Support: {ADMIN_USERNAME}",
        reply_markup=kb_inline,
        parse_mode="Markdown"
    )
    
    bot.send_message(m.chat.id, "Use the back button to return:", reply_markup=kb_reply)

@bot.message_handler(func=lambda m: m.text == "✅ Approve/Reject Task" and m.chat.id == ADMIN_ID)
def approve_reject_menu(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    submissions = load(SUBMISSIONS_FILE)
    pending = [s for s in submissions.values() if s["status"] == "pending"]
    
    text = (
        f"✅ **TASK SUBMISSIONS**\n\n"
        f"⏳ Pending: {len(pending)}\n\n"
        f"New submissions will appear above with approve/reject buttons."
    )
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

@bot.message_handler(func=lambda m: m.text == "📢 Broadcast" and m.chat.id == ADMIN_ID)
def broadcast_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "📝 Type your broadcast message:", reply_markup=kb)
    admin_state[m.chat.id] = "broadcast_message"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "broadcast_message" and m.chat.id == ADMIN_ID)
def broadcast_message(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    temp_data[m.chat.id] = {"broadcast": m.text[:4000]}
    
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("✅ Send to All", callback_data="confirm_broadcast"),
        types.InlineKeyboardButton("❌ Cancel", callback_data="cancel_broadcast")
    )
    
    msg = bot.send_message(
        m.chat.id,
        f"📢 **PREVIEW:**\n\n{m.text}\n\nSend to all users?",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    last_message[m.chat.id] = msg.message_id

@bot.callback_query_handler(func=lambda c: c.data in ["confirm_broadcast", "cancel_broadcast"])
def handle_broadcast(c):
    if c.data == "cancel_broadcast":
        bot.edit_message_text("❌ Broadcast cancelled.", c.message.chat.id, c.message.message_id)
        admin_state.pop(c.message.chat.id, None)
        return
    
    users = load(USERS_FILE)
    message = temp_data.get(c.message.chat.id, {}).get("broadcast", "")
    
    bot.edit_message_text("⏳ Sending broadcast...", c.message.chat.id, c.message.message_id)
    
    success = 0
    failed = 0
    
    for user_id in users:
        try:
            bot.send_message(user_id, f"📢 **ANNOUNCEMENT**\n\n{message}", parse_mode="Markdown")
            success += 1
        except:
            failed += 1
    
    send_and_track(
        c.message.chat.id,
        f"✅ Broadcast complete!\n\n"
        f"✅ Sent: {success}\n"
        f"❌ Failed: {failed}",
        reply_markup=admin_menu()
    )
    
    admin_state.pop(c.message.chat.id, None)
    temp_data.pop(c.message.chat.id, None)

@bot.message_handler(func=lambda m: m.text == "💬 Message User" and m.chat.id == ADMIN_ID)
def message_user_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "🆔 Enter User ID:", reply_markup=kb)
    admin_state[m.chat.id] = "message_user_id"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "message_user_id" and m.chat.id == ADMIN_ID)
def message_user_id(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state.pop(m.chat.id, None)
        return send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())
    
    if not validate_user_id(m.text):
        send_and_track(m.chat.id, "❌ Invalid User ID!", reply_markup=back_button())
    
    temp_data[m.chat.id] = {"target_user": m.text}
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    send_and_track(m.chat.id, "✍️ Type your message:", reply_markup=kb)
    admin_state[m.chat.id] = "message_user_text"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "message_user_text" and m.chat.id == ADMIN_ID)
def message_user_text(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "message_user_id"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.add("🔙 Back")
        return send_and_track(m.chat.id, "🆔 Enter User ID:", reply_markup=kb)
    
    target = temp_data[m.chat.id]["target_user"]
    
    try:
        bot.send_message(target, f"💬 **Message from Admin:**\n\n{m.text[:4000]}", parse_mode="Markdown")
        send_and_track(m.chat.id, "✅ Message sent!", reply_markup=admin_menu())
    except:
        send_and_track(m.chat.id, "❌ Failed to send message!", reply_markup=admin_menu())
    
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

@bot.message_handler(func=lambda m: m.text == "ℹ️ Users Info" and m.chat.id == ADMIN_ID)
def users_info(m):
    delete_message_safe(m.chat.id, m.message_id)
    users = load(USERS_FILE)
    wallets = load(WALLETS_FILE)
    tasks = load(TASKS_FILE)
    submissions = load(SUBMISSIONS_FILE)
    withdrawals = load(WITHDRAWALS_FILE)
    referrals = load(REFERRALS_FILE)
    
    total_users = len(users)
    total_naira = sum(w.get("naira", 0) for w in wallets.values())
    total_dollar = sum(w.get("dollar", 0) for w in wallets.values())
    total_completed = sum(w.get("completed_tasks", 0) for w in wallets.values())
    total_pending_tasks = sum(w.get("pending_tasks", 0) for w in wallets.values())
    
    active_tasks = len([t for t in tasks.values() if t.get("status") == "active"])
    pending_submissions = len([s for s in submissions.values() if s["status"] == "pending"])
    pending_withdrawals = len([w for w in withdrawals.values() if w["status"] == "pending"])
    total_referrals = sum(len(refs) for refs in referrals.values())
    
    text = (
        f"ℹ️ **SYSTEM STATISTICS**\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👥 **USERS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Total Users: {total_users}\n"
        f"Total Referrals: {total_referrals}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💰 **TOTAL BALANCES**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"₦ Naira: ₦{total_naira:,.2f}\n"
        f"💵 Dollar: ${total_dollar:,.2f}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🎯 **TASKS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Active Tasks: {active_tasks}\n"
        f"Completed Tasks: {total_completed}\n"
        f"Pending Submissions: {pending_submissions}\n"
        f"Pending User Tasks: {total_pending_tasks}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"💸 **WITHDRAWALS**\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Pending Requests: {pending_withdrawals}\n"
    )
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=back_button())

@bot.message_handler(func=lambda m: m.text == "⚙️ Admin Dashboard" and m.chat.id == ADMIN_ID)
def admin_dashboard(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    user_state.pop(m.chat.id, None)
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)
    
    send_and_track(m.chat.id, "⚙️ Admin Dashboard", reply_markup=admin_menu())

@bot.message_handler(func=lambda m: m.text == "🔙 Back to Main" and m.chat.id == ADMIN_ID)
def back_to_main_admin(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    user_state.pop(m.chat.id, None)
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)
    user_role.pop(m.chat.id, None)
    
    users = load(USERS_FILE)
    user_id = str(m.chat.id)
    
    full_name = m.from_user.first_name or "Admin"
    if m.from_user.last_name:
        full_name += f" {m.from_user.last_name}"
    
    referral_link = f"{BOT_LINK}?start={user_id}"
    
    welcome_msg = (
        f"👋 Welcome back, {full_name}! 🎉\n\n"
        "🤖 **SOCIAL MEDIA EARNING** 🤖\n\n"
        "Earn money by completing simple social media tasks! 💰\n\n"
        "invite your friend and earn reward\n\n"
        "after he is completed 10 task using your invitation link\n\n"
        "Please select your role to continue:"
    )
    
    send_and_track(
        m.chat.id,
        welcome_msg,
        reply_markup=get_role_selection_menu(),
        parse_mode="Markdown"
    )

@bot.message_handler(func=lambda m: m.text == "📊 Edit Tasks Count" and admin_state.get(m.chat.id) == "manage_user_menu" and m.chat.id == ADMIN_ID)
def edit_tasks_count_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.row("✅ Completed Tasks")
    kb.row("⏳ Pending Tasks")
    kb.row("🔙 Back")
    
    send_and_track(m.chat.id, "Select which task count to edit:", reply_markup=kb)
    admin_state[m.chat.id] = "edit_tasks_type"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "edit_tasks_type" and m.chat.id == ADMIN_ID)
def edit_tasks_type(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_id = temp_data[m.chat.id]["managing_user"]
        admin_state[m.chat.id] = "manage_user_id"
        return manage_user_id(types.SimpleNamespace(chat=types.SimpleNamespace(id=m.chat.id), text=user_id, message_id=m.message_id))
    
    if "Completed" in m.text:
        temp_data[m.chat.id]["edit_task_type"] = "completed_tasks"
        task_label = "Completed"
    else:
        temp_data[m.chat.id]["edit_task_type"] = "pending_tasks"
        task_label = "Pending"
    
    user_id = temp_data[m.chat.id]["managing_user"]
    wallet = get_wallet(user_id)
    current_value = wallet[temp_data[m.chat.id]["edit_task_type"]]
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(
        m.chat.id,
        f"📊 **EDIT {task_label.upper()} TASKS**\n\n"
        f"Current value: {current_value}\n\n"
        f"Enter new value:",
        reply_markup=kb,
        parse_mode="Markdown"
    )
    admin_state[m.chat.id] = "edit_tasks_value"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "edit_tasks_value" and m.chat.id == ADMIN_ID)
def edit_tasks_value(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        admin_state[m.chat.id] = "edit_tasks_type"
        kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
        kb.row("✅ Completed Tasks")
        kb.row("⏳ Pending Tasks")
        kb.row("🔙 Back")
        return send_and_track(m.chat.id, "Select which task count to edit:", reply_markup=kb)
    
    try:
        new_value = int(m.text)
        if new_value < 0:
            send_and_track(m.chat.id, "❌ Value must be 0 or positive!", reply_markup=back_button())
            return
    except:
        send_and_track(m.chat.id, "❌ Invalid number!", reply_markup=back_button())
        return
    
    user_id = temp_data[m.chat.id]["managing_user"]
    task_type = temp_data[m.chat.id]["edit_task_type"]
    
    wallets = load(WALLETS_FILE)
    old_value = wallets[user_id][task_type]
    wallets[user_id][task_type] = new_value
    save(WALLETS_FILE, wallets)
    
    users = load(USERS_FILE)
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    task_label = "Completed" if task_type == "completed_tasks" else "Pending"
    
    send_and_track(
        m.chat.id,
        f"✅ **TASKS COUNT UPDATED**\n\n"
        f"User: {user_name}\n"
        f"Task Type: {task_label}\n"
        f"Old Value: {old_value}\n"
        f"New Value: {new_value}",
        reply_markup=admin_menu(),
        parse_mode="Markdown"
    )
    
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

@bot.message_handler(func=lambda m: m.text == "💸 View Withdrawals" and admin_state.get(m.chat.id) == "manage_user_menu" and m.chat.id == ADMIN_ID)
def view_user_withdrawals(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    user_id = temp_data[m.chat.id]["managing_user"]
    withdrawals = load(WITHDRAWALS_FILE)
    users = load(USERS_FILE)
    
    user_withdrawals = [(w_id, w) for w_id, w in withdrawals.items() if w["user_id"] == user_id]
    
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    text = f"💸 **WITHDRAWALS FOR {user_name}**\n\n"
    
    if not user_withdrawals:
        text += "No withdrawals found."
    else:
        pending = [w for _, w in user_withdrawals if w["status"] == "pending"]
        approved = [w for _, w in user_withdrawals if w["status"] == "approved"]
        cancelled = [w for _, w in user_withdrawals if w["status"] == "cancelled"]
        
        text += f"⏳ Pending: {len(pending)}\n"
        text += f"✅ Approved: {len(approved)}\n"
        text += f"❌ Cancelled: {len(cancelled)}\n\n"
        
        text += "━━━━━━━━━━━━━━━━━━\n"
        text += "Recent Withdrawals:\n\n"
        
        for w_id, w in sorted(user_withdrawals, key=lambda x: x[1]["requested"], reverse=True)[:5]:
            symbol = "₦" if w["currency"] == "naira" else "$"
            status_emoji = "✅" if w["status"] == "approved" else "⏳" if w["status"] == "pending" else "❌"
            
            text += f"{status_emoji} {symbol}{w['total']:.2f} - {w['status'].upper()}\n"
            text += f"Date: {w['requested'][:16]}\n"
            text += f"ID: `{w_id}`\n\n"
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(m.chat.id, text, parse_mode="Markdown", reply_markup=kb)

@bot.message_handler(func=lambda m: m.text == "💳 Edit Bank Details" and admin_state.get(m.chat.id) == "manage_user_menu" and m.chat.id == ADMIN_ID)
def edit_bank_details_start(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    user_id = temp_data[m.chat.id]["managing_user"]
    bank_data = load(BANK_FILE)
    
    if user_id in bank_data:
        text = (
            f"💳 **CURRENT PAYMENT DETAILS**\n\n"
            f"Type: {bank_data[user_id].get('type', 'N/A')}\n\n"
            f"Details:\n{bank_data[user_id].get('details', 'N/A')}\n\n"
            f"Send new payment details to replace:"
        )
    else:
        text = "💳 **NO PAYMENT DETAILS SET**\n\nSend payment details:"
    
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=False)
    kb.add("🔙 Back")
    
    send_and_track(m.chat.id, text, reply_markup=kb, parse_mode="Markdown")
    admin_state[m.chat.id] = "edit_bank_details_text"

@bot.message_handler(func=lambda m: admin_state.get(m.chat.id) == "edit_bank_details_text" and m.chat.id == ADMIN_ID)
def edit_bank_details_save(m):
    delete_message_safe(m.chat.id, m.message_id)
    
    if m.text == "🔙 Back":
        user_id = temp_data[m.chat.id]["managing_user"]
        admin_state[m.chat.id] = "manage_user_id"
        return manage_user_id(types.SimpleNamespace(chat=types.SimpleNamespace(id=m.chat.id), text=user_id, message_id=m.message_id))
    
    user_id = temp_data[m.chat.id]["managing_user"]
    bank_data = load(BANK_FILE)
    users = load(USERS_FILE)
    
    bank_data[user_id] = {
        "type": "Admin Updated",
        "details": m.text[:500],
        "updated": str(datetime.now())
    }
    save(BANK_FILE, bank_data)
    
    user_name = users.get(user_id, {}).get("name", "Unknown")
    
    send_and_track(
        m.chat.id,
        f"✅ **PAYMENT DETAILS UPDATED**\n\n"
        f"User: {user_name}\n"
        f"ID: `{user_id}`\n\n"
        f"New Details:\n{m.text[:500]}",
        reply_markup=admin_menu(),
        parse_mode="Markdown"
    )
    
    admin_state.pop(m.chat.id, None)
    temp_data.pop(m.chat.id, None)

# ================= FALLBACK HANDLER =================

@bot.message_handler(func=lambda m: True)
def fallback(m):
    """Handle unrecognized messages"""
    delete_message_safe(m.chat.id, m.message_id)
    
    if user_role.get(m.chat.id) == "earner":
        send_and_track(
            m.chat.id,
            "❌ I didn't understand that command.\n\nPlease use the menu buttons below.",
            reply_markup=earner_menu(m.chat.id)
        )
    elif user_role.get(m.chat.id) == "advertiser":
        send_and_track(
            m.chat.id,
            "❌ I didn't understand that command.\n\nPlease use the menu buttons below.",
            reply_markup=advertiser_menu()
        )
    elif m.chat.id == ADMIN_ID and admin_state.get(m.chat.id):
        pass
    elif m.chat.id == ADMIN_ID:
        send_and_track(
            m.chat.id,
            "❌ I didn't understand that command.\n\nPlease use the menu buttons below.",
            reply_markup=admin_menu()
        )
    else:
        send_and_track(
            m.chat.id,
            "👋 Welcome! Please select your role:",
            reply_markup=get_role_selection_menu()
        )

# ================= RUN BOT =================

if __name__ == "__main__":
    print("=" * 60)
    print("🤖 SOCIAL MEDIA EARNING BOT")
    print("=" * 60)
    print("🏢 Company: Mobile Skills Network")
    print(f"👤 Admin ID: {ADMIN_ID}")
    print(f"🔗 Bot Link: {BOT_LINK}")
    print("=" * 60)
    print("\n✅ FEATURES ENABLED:")
    print("  • Task Management (Create, Delete, Approve)")
    print("  • User Wallet System (Naira & USDT)")
    print("  • Currency Exchange (Naira ↔ USDT)")
    print("  • Withdrawal System (with fees)")
    print("  • Referral Rewards (₦30 after 10 tasks)")
    print("  • Payment Details Management")
    print("  • Admin Dashboard")
    print("  • Broadcast System")
    print("\n🔐 SECURE TRANSFER SYSTEM:")
    print("  • 4-Digit PIN Protection")
    print("  • PIN Hashing (PBKDF2 + SHA256)")
    print("  • Failed Attempts Lockout (3 attempts = 30 min lock)")
    print("  • Rate Limiting (5 transfers/day)")
    print("  • Max Transfer Amount (₦100,000)")
    print("  • Transfer Audit Logging")
    print("  • Admin Transfer Reversal")
    print("  • Admin PIN Management (Reset, View Status)")
    print("  • Atomic Transactions")
    print("  • Anti-Replay Protection")
    print("\n📁 DATA FILES:")
    print(f"  • {USERS_FILE}")
    print(f"  • {TASKS_FILE}")
    print(f"  • {REFERRALS_FILE}")
    print(f"  • {SUBMISSIONS_FILE}")
    print(f"  • {WALLETS_FILE}")
    print(f"  • {BANK_FILE}")
    print(f"  • {WITHDRAWALS_FILE}")
    print(f"  • {EXCHANGES_FILE}")
    print(f"  • {PIN_FILE}")
    print(f"  • {TRANSFER_AUDIT_FILE}")
    print(f"  • {TRANSFER_LIMITS_FILE}")
    print("=" * 60)
    print("\n🚀 Bot is now running...")
    print("Press Ctrl+C to stop\n")
    
    try:
        bot.infinity_polling(timeout=10, long_polling_timeout=5)
    except KeyboardInterrupt:
        print("\n\n⚠️  Bot stopped by user")
        print("=" * 60)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        print("=" * 60)