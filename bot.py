import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from telegram import Update
from telegram.error import BadRequest, Forbidden
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

import database
import join_detector
import link_checker
from health_check import start_health_check_server
from repetition_detector import check_repetition
from spam_detector import SPAM_DELETE_THRESHOLD, SPAM_WARN_THRESHOLD, analyze_message

# مسیر فایل .env رو دقیقاً کنار خود bot.py پیدا می‌کنیم
# (اینطوری فرقی نمی‌کنه از کجا اسکریپت رو اجرا کرده باشی)
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)
BOT_TOKEN = os.getenv("BOT_TOKEN")

# اختیاری: اگه به تلگرام دسترسی مستقیم نداری (مثلاً به VPN/پراکسی نیاز داری)
# آدرس پراکسی رو توی .env بذار، مثلاً:
#   PROXY_URL=http://127.0.0.1:10809
#   PROXY_URL=socks5://127.0.0.1:1080
PROXY_URL = os.getenv("PROXY_URL")

# اختیاری: کلید Google Safe Browsing API برای چک لینک‌های مخرب
# اگه تنظیم نشه، این قابلیت فقط نادیده گرفته می‌شه
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """جواب به دستور /start"""
    await update.message.reply_text(
        "ربات ضد اسپم فعاله ✅\n"
        "برای اینکه بتونم پیام‌های گروه رو بررسی کنم، باید من رو ادمین گروه کنی.\n"
        "برای دیدن دستورات مدیریتی، /help رو بزن."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """جواب به دستور /help"""
    await update.effective_message.reply_text(
        "📋 دستورات مدیریتی (فقط برای ادمین‌های گروه):\n\n"
        "روی پیام فرد موردنظر ریپلای کن و یکی از این‌ها رو بزن:\n"
        "/whitelist — این کاربر رو از بررسی اسپم معاف کن\n"
        "/unwhitelist — این کاربر رو دوباره تحت بررسی قرار بده\n"
        "/ban — این کاربر رو از گروه اخراج کن\n"
        "/report — گزارش آماری این کاربر رو ببین"
    )


async def _get_admin_ids(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> set[int]:
    admins = await context.bot.get_chat_administrators(chat_id)
    return {admin.user.id for admin in admins}


async def _require_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """اگه فرستنده‌ی دستور ادمین گروه نباشه، پیام خطا می‌ده و False برمی‌گردونه."""
    chat = update.effective_chat
    user = update.effective_user
    admin_ids = await _get_admin_ids(context, chat.id)
    if user.id not in admin_ids:
        await update.effective_message.reply_text(
            "⛔ این دستور فقط برای ادمین‌های گروه مجازه."
        )
        return False
    return True


def _get_target_user(update: Update):
    """کاربر هدف رو از روی پیام ریپلای‌شده پیدا می‌کنه. اگه ریپلای نبود None برمی‌گردونه."""
    message = update.effective_message
    if message.reply_to_message and message.reply_to_message.from_user:
        return message.reply_to_message.from_user
    return None


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    هر پیام متنی گروه رو تحلیل می‌کنه:
    - امتیاز >= آستانه‌ی حذف: پیام حذف می‌شه، در دیتابیس ثبت می‌شه
    - امتیاز بین آستانه‌ی هشدار و حذف: فقط لاگ می‌شه (برای بازبینی)، حذف نمی‌شه
    - کمتر از اون: پیام عادیه
    """
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not message.text:
        return  # فعلاً فقط پیام‌های متنی رو چک می‌کنیم

    database.touch_user(user.id, user.first_name)

    if database.is_whitelisted(user.id):
        logger.info(f"[سفیدلیست] {user.first_name}: {message.text}")
        return

    result = analyze_message(message.text)
    score = result["score"]
    reasons = result["reasons"]

    urls = link_checker.extract_urls(message.text)
    if urls:
        link_result = await link_checker.check_urls(urls, SAFE_BROWSING_API_KEY)
        if link_result["is_malicious"]:
            score += link_result["score"]
            reasons.append(
                f'لینک مخرب تأیید شده توسط Google Safe Browsing '
                f'(+{link_result["score"]})'
            )

    repetition = check_repetition(user.id, message.text)
    if repetition["is_repeated"]:
        score += repetition["score"]
        reasons.append(
            f'پیام تکراری ({repetition["repeat_count"]} بار مشابه در {60} ثانیه‌ی اخیر) '
            f'(+{repetition["score"]})'
        )

    # اگه پیام از قبل یکم مشکوک بود (امتیازش صفر نیست) و فرستنده هم تازه‌وارده،
    # این ترکیب (جوین + بلافاصله پیام مشکوک) امتیاز اضافه می‌گیره
    if score > 0:
        new_user_bonus = join_detector.get_new_user_bonus(user.id)
        if new_user_bonus:
            score += new_user_bonus
            reasons.append(f"کاربر تازه‌وارد (کمتر از ۵ دقیقه از جوین) (+{new_user_bonus})")

    reasons_text = "، ".join(reasons) if reasons else "-"

    if score >= SPAM_DELETE_THRESHOLD:
        logger.warning(
            f'🚫 امتیاز اسپم {score} در "{chat.title}" از {user.first_name} '
            f"(id={user.id}) | دلایل: {reasons_text}\nمتن پیام: {message.text}"
        )
        database.increment_spam_count(user.id)
        database.log_flagged_message(
            user.id, chat.id, chat.title, message.text, score, reasons, "deleted"
        )
        try:
            await message.delete()
            logger.info("✅ پیام با موفقیت حذف شد.")
        except (Forbidden, BadRequest) as e:
            logger.error(
                f"❌ نتونستم پیام رو حذف کنم. مطمئن شو ربات ادمین گروهه "
                f"و دسترسی 'Delete messages' داره. خطا: {e}"
            )

    elif score >= SPAM_WARN_THRESHOLD:
        logger.warning(
            f'⚠️ امتیاز مشکوک {score} (حذف نشد) در "{chat.title}" از {user.first_name} '
            f"(id={user.id}) | دلایل: {reasons_text}\nمتن پیام: {message.text}"
        )
        database.log_flagged_message(
            user.id, chat.id, chat.title, message.text, score, reasons, "warned"
        )

    else:
        logger.info(
            f"[{chat.title or chat.id}] {user.first_name} (id={user.id}): {message.text}"
        )


async def handle_new_members(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    وقتی یک یا چند عضو جدید به گروه اضافه می‌شن صدا زده می‌شه.
    زمان جوین هر کدوم رو ثبت می‌کنه و اگه جوین‌ها دسته‌جمعی و مشکوک بودن هشدار می‌ده.
    """
    chat = update.effective_chat
    message = update.effective_message

    for member in message.new_chat_members:
        result = join_detector.record_join(chat.id, member.id)
        logger.info(
            f'👤 عضو جدید در "{chat.title}": {member.first_name} (id={member.id})'
        )

        if result["is_flood"]:
            logger.warning(
                f'🚨 جوین دسته‌جمعی مشکوک در "{chat.title}": '
                f'{result["recent_join_count"]} عضو جدید در '
                f"{join_detector.FLOOD_JOIN_WINDOW_SECONDS} ثانیه‌ی اخیر!"
            )
            try:
                await context.bot.send_message(
                    chat_id=chat.id,
                    text=(
                        "⚠️ تعداد غیرعادی عضو جدید در بازه‌ی زمانی کوتاهی به گروه "
                        "اضافه شدن. ادمین‌ها لطفاً بررسی کنند."
                    ),
                )
            except (Forbidden, BadRequest) as e:
                logger.error(f"نتونستم پیام هشدار جوین دسته‌جمعی رو بفرستم: {e}")


async def whitelist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _require_admin(update, context):
        return

    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text(
            "روی پیام فرد موردنظر ریپلای کن و بنویس /whitelist"
        )
        return

    database.set_whitelisted(target.id, True)
    await update.effective_message.reply_text(
        f"✅ {target.first_name} به لیست سفید اضافه شد. پیام‌هاش دیگه بررسی نمی‌شن."
    )
    logger.info(
        f"ادمین {update.effective_user.first_name} کاربر {target.first_name} "
        f"(id={target.id}) رو سفیدلیست کرد."
    )


async def unwhitelist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _require_admin(update, context):
        return

    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text(
            "روی پیام فرد موردنظر ریپلای کن و بنویس /unwhitelist"
        )
        return

    database.set_whitelisted(target.id, False)
    await update.effective_message.reply_text(
        f"↩️ {target.first_name} از لیست سفید خارج شد و دوباره بررسی می‌شه."
    )


async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _require_admin(update, context):
        return

    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text(
            "روی پیام فرد موردنظر ریپلای کن و بنویس /ban"
        )
        return

    chat = update.effective_chat
    try:
        await context.bot.ban_chat_member(chat_id=chat.id, user_id=target.id)
        await update.effective_message.reply_text(f"🚫 {target.first_name} از گروه بن شد.")
        logger.warning(
            f"ادمین {update.effective_user.first_name} کاربر {target.first_name} "
            f"(id={target.id}) رو بن کرد."
        )
    except (Forbidden, BadRequest) as e:
        await update.effective_message.reply_text(
            "❌ نتونستم این کاربر رو بن کنم. مطمئن شو ربات دسترسی 'Ban users' داره."
        )
        logger.error(f"خطا در بن‌کردن: {e}")


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _require_admin(update, context):
        return

    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text(
            "روی پیام فرد موردنظر ریپلای کن و بنویس /report"
        )
        return

    stats = database.get_user_stats(target.id)
    if not stats:
        await update.effective_message.reply_text("هیچ اطلاعاتی از این کاربر ثبت نشده.")
        return

    await update.effective_message.reply_text(
        f"📊 گزارش {target.first_name}:\n"
        f"تعداد کل پیام‌ها: {stats['message_count']}\n"
        f"تعداد پیام‌های اسپم: {stats['spam_count']}\n"
        f"سفیدلیست: {'بله' if stats['is_whitelisted'] else 'خیر'}\n"
        f"اولین‌بار دیده‌شده: {stats['first_seen']}"
    )


def main():
    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN پیدا نشد. یه فایل .env بساز (از روی .env.example) "
            "و توکن ربات رو توش بذار."
        )

    database.init_db()
    logger.info("دیتابیس آماده شد.")

    start_health_check_server()
    logger.info("سرور health check راه‌اندازی شد.")

    builder = Application.builder().token(BOT_TOKEN)

    if PROXY_URL:
        logger.info(f"استفاده از پراکسی: {PROXY_URL}")
        builder = builder.proxy(PROXY_URL).get_updates_proxy(PROXY_URL)

    app = builder.build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("whitelist", whitelist_command))
    app.add_handler(CommandHandler("unwhitelist", unwhitelist_command))
    app.add_handler(CommandHandler("ban", ban_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(
        MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_members)
    )
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("ربات در حال اجراست... (برای توقف Ctrl+C بزن)")
    app.run_polling()


if __name__ == "__main__":
    main()
