from flask import Flask

app = Flask(__name__)
app.config.from_object('conf')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

from app import flaskr
