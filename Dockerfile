FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY mobile_server.py .
COPY mobile_order.html .

# Data directory for SQLite
RUN mkdir -p /app/.hbillsoft

EXPOSE 5050

CMD ["python", "-c", "from mobile_server import start_mobile_server, create_flask_app, init_pending_table; import time; init_pending_table(); app = create_flask_app(); app.run(host='0.0.0.0', port=5050, debug=False)"]
