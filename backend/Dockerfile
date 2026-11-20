FROM docker.io/library/python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY models ./models
# uid 10001 must match RULES_OWNER_UID in the resolver entrypoint
RUN useradd --system --uid 10001 --no-create-home app && mkdir -p /srv/data /rules && chown -R app /srv/data /rules
USER app
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status==200 else 1)"
# One worker on purpose: behavioural state and WebSocket clients live in process memory.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
