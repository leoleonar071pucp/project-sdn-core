FROM python:3.12-alpine
WORKDIR /app/m1_auth
COPY requirements.txt .
RUN pip install -r requirements.txt
CMD ["python", "web.py"]