import os

from flask import Flask, jsonify

app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/getmarkerlist')
def marker_list():
    dblist = os.listdir("databases/")
    dbdict = {}
    for idx, item in enumerate(dblist):
        dbdict[idx] = item[:-3]

    return jsonify(dbdict)


app.run(debug=True)
