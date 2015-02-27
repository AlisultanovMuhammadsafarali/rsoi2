from app import app
import os

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flaskr1.db'),
    DEBUG=True,
    SECRET_KEY='3423ewerg132fdvij923dgjh238vdwjh47sdjk112',
))
