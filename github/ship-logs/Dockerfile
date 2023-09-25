FROM python:3-slim AS builder
ADD . /app
WORKDIR /app
RUN pip install --target=/app -r requirements.txt
ENV PYTHONPATH /app
ENV PYTHONUNBUFFERED 1
ENV ENVVARPREFIX INPUT_
CMD ["python", "/app/logshipper.py"]
