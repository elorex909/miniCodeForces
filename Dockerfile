# 1. الصورة الأساسية: نستخدم أحدث إصدار مستقر من Python
FROM python:3.12-slim

# 2. تثبيت g++ والأدوات الأساسية
#    يجب أن تتم هذه الخطوة قبل تثبيت متطلبات Python
RUN apt-get update && \
    apt-get install -y build-essential \
    && rm -rf /var/lib/apt/lists/*

# 3. تعيين مجلد العمل
WORKDIR /usr/src/app

# 4. نسخ وتثبيت متطلبات Python (بما فيها gunicorn)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 5. نسخ باقي ملفات التطبيق
COPY . .

# 6. أمر تشغيل التطبيق (Start Command)
#    نستخدم المسار الكامل لملف gunicorn التنفيذي (/usr/local/bin/)
#    لحل مشكلة "No module named gunicorn" نهائياً.
ENV FLASK_APP=app.py
ENV PORT 5000
CMD ["/usr/local/bin/gunicorn", "--bind", "0.0.0.0:$PORT", "app:app"]
