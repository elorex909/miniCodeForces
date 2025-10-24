# Dockerfile

# 1. الصورة الأساسية: نستخدم صورة Python رسمية (3.11 أو 3.12 مستقر)
FROM python:3.11-slim

# 2. تثبيت g++ والأدوات الأساسية
# 'build-essential' هي الحزمة التي تحتوي على g++
RUN apt-get update && \
    apt-get install -y build-essential \
    && rm -rf /var/lib/apt/lists/*

# 3. تعيين مجلد العمل
WORKDIR /usr/src/app

# 4. نسخ وتثبيت متطلبات Python (يجب أن تحتوي على Flask و gunicorn)
COPY requirements.txt ./
# تثبيت الحزم
RUN pip install --no-cache-dir -r requirements.txt

# 5. نسخ باقي ملفات التطبيق (app.py, users.json, etc.)
COPY . .

# 6. إضافة مسار الملفات التنفيذية (لتصحيح مشكلة gunicorn)
ENV PATH="/usr/local/bin:$PATH" 

# لا نستخدم CMD هنا، سنستخدم Procfile
