FROM docker.io/alpine:latest

RUN apk add --no-cache python3 py3-pip

WORKDIR /app

COPY config.ini /app/config.ini
COPY middleware.py /app/middleware.py

RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

RUN pip install --no-cache-dir flask requests werkzeug urllib3 gunicorn

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "middleware:app"]