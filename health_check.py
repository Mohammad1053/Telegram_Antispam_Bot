"""
سرور HTTP بسیار سبک، فقط برای جواب‌دادن به health check های Render (یا هر
سرویس میزبانی مشابه که برای "Web Service" انتظار داره یه پورت HTTP باز باشه).

چرا لازمه: ربات ما با run_polling() کار می‌کنه، یعنی خودش به تلگرام وصل
می‌شه، نه برعکس - پس هیچ سروری روی هیچ پورتی گوش نمی‌ده. اگه Render (یا
مشابهش) نتونه health check رو جواب بگیره، فکر می‌کنه سرویس خرابه و یه
نمونه‌ی جدید از ربات رو بالا می‌آره؛ نتیجه‌ش دو نمونه‌ی هم‌زمان و خطای
Conflict روی getUpdates تلگراممه. این فایل با باز کردن یه پورت ساده و
جواب‌دادن "OK"، از این اتفاق جلوگیری می‌کنه.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("ربات در حال اجراست.".encode("utf-8"))

    def log_message(self, format, *args):
        # لاگ‌های پیش‌فرض هر درخواست HTTP رو خاموش می‌کنیم که ترمینال شلوغ نشه
        pass


def start_health_check_server():
    """
    یه سرور HTTP ساده رو توی یه thread جدا (در پس‌زمینه) اجرا می‌کنه.
    پورت رو از متغیر محیطی PORT می‌خونه (Render خودش این متغیر رو ست می‌کنه).
    """
    port = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), _HealthCheckHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
