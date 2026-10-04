برنامه چت (نسخه آفلاین لینوکس)
==============================

این پکیج همه کتابخانه‌های لازم را داخل خودش دارد.
روی سیستم مقصد به اینترنت و نصب هیچ کتابخانه‌ای با pip نیاز نیست.

تنها پیش‌نیاز: لینوکس ۶۴ بیتی + پایتون ۳.۱۲ (فقط خود پایتون، بدون هیچ پکیجی)

  python3 --version     # باید 3.12.x باشد

اجرای سریع
----------
  tar -xzf chat-app-linux-x86_64.tar.gz
  cd chat-app
  ./chat-app

بعد مرورگر را باز کنید: http://127.0.0.1:8001
(با متغیر PORT می‌توانید پورت را عوض کنید: PORT=8002 ./chat-app)

نصب دائمی (اختیاری)
-------------------
  ./install.sh
  chat-app

داده‌ها کجا ذخیره می‌شوند؟
--------------------------
دیتابیس (chat.db) و کلید رمزنگاری (.chat_secret) به‌صورت خودکار در
پوشه‌ی data کنار برنامه ساخته می‌شوند. با متغیر CHAT_DATA_DIR
می‌توانید جای دیگری تعیین کنید.

تنظیمات (اختیاری): فایل .env کنار برنامه یا متغیرهای محیطی —
HOST، PORT، REGISTRATION_ENABLED (بستن ثبت‌نام: true/false)،
CHAT_DATA_DIR و CHAT_ENCRYPTION_KEY.

هشدار مهم: اگر فایل .chat_secret پاک شود، پیام‌های ذخیره‌شده
برای همیشه غیرقابل خواندن می‌شوند. از آن بکاپ بگیرید.

CHAT APP (offline Linux bundle)
===============================
Self-contained: all Python libraries are vendored inside lib/.
No pip installs, no internet needed on the target machine.

Only requirement: Linux x86_64 + stock Python 3.12 (no packages).

Quick start:
  tar -xzf chat-app-linux-x86_64.tar.gz
  cd chat-app
  ./chat-app        # then open http://127.0.0.1:8001

Optional install: ./install.sh   -> then run: chat-app
Data (chat.db + .chat_secret) is created in ./data next to the bundle
(override with CHAT_DATA_DIR). Back up .chat_secret: losing it makes
stored messages permanently unreadable.
