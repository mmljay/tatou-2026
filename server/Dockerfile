# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd --gid "$APP_GID" tatou \
 && useradd --uid "$APP_UID" --gid "$APP_GID" --home-dir /app --no-create-home --shell /usr/sbin/nologin tatou

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY --chown=root:root src /app/src
COPY --chown=root:root flag /app/flag
COPY --chown=root:root entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

RUN mkdir -p /app/storage \
 && chown tatou:tatou /app/storage \
 && chmod -R a+rX /app/src \
 && chmod 0400 /app/flag \
 && chmod 0555 /app/entrypoint.sh

USER tatou

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

