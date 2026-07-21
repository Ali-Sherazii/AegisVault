
import os
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Welcome to the REAL backend!"

@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200

@app.route("/search")
def search():
    return "Search endpoint reached."

@app.route("/admin")
def admin():
    return "Admin page (should be blocked if WAF works)."

if __name__ == "__main__":
    # Render (and similar PaaS) inject PORT and require the service to bind to it.
    port = int(os.environ.get("PORT") or os.environ.get("BACKEND_PORT", 8000))
    app.run(host=os.environ.get("BACKEND_HOST", "0.0.0.0"), port=port)
