from app import app

import sqlite3
import hashlib
import json
import time
import random

from flask import request, session, g, redirect, url_for, abort, \
                  render_template, flash, make_response, jsonify

from datetime import datetime, timedelta


client_id = 1
client_secret = "h1e2l3l4o5f6i7r8s9t10c11l12i13e14n15t"
redirect_uri = "localhost:5000"
shift = 3


def connect_db():
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def get_code(user_fk, uri):
    code = str(random.randrange(256**15))

    db = get_db()
    db.execute('insert into sess (access_token, refresh_token, redirect_uri, user_fk, logged_in, code) values (?, ?, ?, ?, ?, ?)', [0, 0, uri, user_fk, 1, code])
    db.commit()

    return code


@app.route('/oauth', methods=['GET', 'POST'])
def oauth():
    if not ('client_id' in request.args and 'redirect_uri' in request.args):
        return jsonify({'error': "Missing parameters"})

    if query_db('select * from clients_app where client_id == ?', [client_id], True) is not None:
        return redirect(url_for('login', redirect_uri=request.args['redirect_uri']))
    else:
        return jsonify({'error': "Invalid client_id"})


@app.route('/oauth2')
def to_auth():
    return redirect(url_for('oauth', client_id=1, redirect_uri=redirect_uri))


@app.route('/token', methods=['GET', 'POST'])
def token():
    if request.method == 'GET':
        if ('client_id' in request.args and 'code' in request.args and
            'client_secret' in request.args and 'redirect_uri' in request.args and
            'grant_type' in request.args):
            if request.args['grant_type'] == 'authorization_code':
                user_sess = query_db('select * from sess where code = ?', [request.args['code']], one=True)

            if request.args['grant_type'] == 'refresh_token' and 'Authorization' in request.headers:
                test = test_refresh(request.headers['Authorization'])
                print "test: ", test
                if test:
                    user_sess = query_db('select * from sess where refresh_token = ?', [request.headers['Authorization']], one=True)
                else:
                    return make_response(jsonify({'error': 'refresh_token is expired'}), 401)

            if user_sess is not None:
                print "in (if user_sess is not None:)"
                access_token = str(random.randrange(256**15))
                refresh_token = str(random.randrange(256**15))
                expire_in = 600
                expire_time = datetime.now()
                expire_refresh = 3600

                db = get_db()
                db.execute('update sess set access_token = ?, refresh_token = ?, expire_in = ?, expire_time = ?, expire_refresh = ?, logged_in = ?  where sess_id = ?',
                    [access_token, refresh_token, expire_in, expire_time, expire_refresh, 1, user_sess['sess_id']])
                db.commit()

                return jsonify({'access_token': access_token, 'token_type': "bearer", 'refresh_token': refresh_token, 'expire_in': expire_in})
            else:
                return make_response(jsonify({'error': 'code is not right'}), 401)

    return make_response(jsonify({"message": "access denied"}), 401)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('ideakeep.html')


def test_token(value):
    token = query_db('select * from sess where access_token = ?', [value], one=True)
    if token is not None:
        t1 = datetime.strptime(token['expire_time'], "%Y-%m-%d %H:%M:%S.%f") + timedelta(seconds=token['expire_in'])
        if t1 > datetime.now():
            return True
    return False


def test_refresh(value):
    refresh_token = query_db('select * from sess where refresh_token = ?', [value], one=True)
    if refresh_token is not None:
        t1 = datetime.strptime(refresh_token['expire_time'], "%Y-%m-%d %H:%M:%S.%f") + timedelta(seconds=refresh_token['expire_refresh'])
        if t1 > datetime.now():
            return True
    return False


def logout1(value):
    db = get_db()
    db.execute('update sess set logged_in = ? where access_token = ?', [0, value])
    db.commit()
    return redirect(url_for('login'))


@app.route('/users')
def users():
    amount_users = query_db('select count(*) from users', one=True)
    return jsonify({'amount_users': amount_users[0]})


@app.route('/me')
def me():
    if 'Authorization' in request.headers:
        if test_token(request.headers['Authorization']):
            user_id = query_db('select user_fk from sess where access_token = ?', [request.headers['Authorization']], one=True)
            user = query_db('select * from users where user_id = ?', [user_id[0]], one=True)
            return jsonify({"name": user['name'], "email": user['email'], "phone": user['phone']})
        else:
            logout1(request.headers['Authorization'])

    return make_response(jsonify({"message": "access denied"}), 401)


@app.route('/show_entries_page/<page>')
def show_entries_page(page):
    if 'Authorization' in request.headers:
        if test_token(request.headers['Authorization']):
            user_id = query_db('select user_fk from sess where access_token = ?', [request.headers['Authorization']], one=True)
            entries = query_db('select title, text from entries, links where links.user_fk = ? and links.entry_fk == entries.entry_id order by entry_id desc', [user_id[0]], False)
            to_ret = []
            maxp = maxpages(user_id[0])
            start = shift*int(page) - shift
            finish = start + shift
            if start >= maxp:
                return make_response(jsonify({"error": "Not found"}), 404)

            for entry in entries[start:finish]:
                to_ret.append({'title': entry[0], 'text': entry[1]})
                print "ret = ", to_ret
            return jsonify({'items': to_ret, 'current': page, 'shown': 1, 'amount': maxp})
        else:
            logout1(request.headers['Authorization'])

    return make_response(jsonify({"message": "access denied"}), 401)


@app.route('/show_entries')
def show_entries():
    if 'Authorization' in request.headers:
        if test_token(request.headers['Authorization']):
            user_id = query_db('select user_fk from sess where access_token = ?', [request.headers['Authorization']], one=True)
            entries = query_db('select title, text from entries, links where links.user_fk = ? and links.entry_fk == entries.entry_id order by entry_id desc', [user_id[0]], False)
            to_ret = []

            user_id = query_db('select user_fk from sess where access_token = ?', [request.headers['Authorization']], one=True)
            maxp = maxpages(user_id[0])
            shown = maxp/shift
            if maxp <= shift:
                shown = 1
            if maxp % 2 == 1:
                shown = maxp/shift + 1

            for entry in entries:
                to_ret.append({'title': entry[0], 'text': entry[1]})
                print "ret = ", to_ret
            return jsonify({'items': to_ret, 'current': 1, 'shown': shown, 'amount': maxp})
        else:
            logout1(request.headers['Authorization'])

    return make_response(jsonify({"message": "access denied"}), 401)


def maxpages(user_id):
    maxpage = query_db('select count(*) from entries, links where links.user_fk = ? and links.entry_fk == entries.entry_id', [user_id], True)
    return maxpage[0]


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    user_fk = session['user_id']

    db.execute('insert into entries (title, text, public) values (?, ?, ?)', [request.form['title'], request.form['text'], 0])
    entry_fk = query_db('select max(entry_id) from entries', one=True)
    db.execute('insert into links (user_fk, entry_fk, time) values(?, ?, ?)', [user_fk, entry_fk[0], datetime.now()])
    db.commit()
    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if (request.method == 'GET'):
        if 'redirect_uri' in request.args:
            redirect_url = request.args['redirect_uri']

    if request.method == 'POST':
        user = query_db('select * from users where name = ?', [request.form['username']], one=True)
        if user is None:
            return jsonify({"error": "No such user"})
        elif request.form['password'] != user['password']:
            return make_response(jsonify({"error": "Invalid password"}), 401)
        else:
            redirect_uri = request.form['redirect_uri']
            flash('You were logged in')
            code = get_code(user['user_id'], redirect_uri)
            resp = "http://" + redirect_uri + "?" + "code=" + code
            return redirect(resp)

    return render_template('login.html', redirect_uri=redirect_url, error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    return render_template("signup.html")


@app.route("/signedup", methods=['GET', 'POST'])
def signedup():
    error = None
    if request.method == 'POST':
        db = get_db()
        name = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        db.execute('insert into users (name, password, email, phone) values (?, ?, ?, ?)',
                    (name, password, email, phone))
        db.commit()

        user = query_db('select * from users where name = ?', [request.form['username']], one=True)
        redirect_uri = request.form['redirect_uri']
        flash('Welcome! Your registration was successful.')
        code = get_code(user['user_id'], redirect_uri)
        resp = "http://" + redirect_uri + "?" + "code=" + code
        return redirect(resp)

    return render_template('signup.html', error=error)


@app.route('/logout')
def logout():
    db = get_db()
    db.execute('select sess set access_token = ?, refresh_token = ?, expire_in = ?, expire_time = ? where sess_id = ?', [access_token, refresh_token, expire_in, expire_time, user_sess['sess_id']])
    db.commit()
    flash('You were logged out')
    return redirect(url_for('login'))
