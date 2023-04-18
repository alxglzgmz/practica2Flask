import sqlite3

from flask import Flask, render_template
import pandas as pd;
app = Flask(__name__)


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


@app.route('/ips/<int:num_ips>')
def top_ips(num_ips):
    conn = sqlite3.connect('practica1.db')
    df_alerts = pd.read_sql_query("SELECT * FROM alerts",conn)

    top_ips = df_alerts['origen'].value_counts().head(num_ips)
    return render_template('top_ips.html', top_ips=top_ips)

@app.route('/devices/<int:num_devices>')
def top_devices(num_devices):
    conn = sqlite3.connect('practica1.db')
    df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id",conn)

    ord_devices = df_devices_analisis.sort_values(by='vulnerabilidades', ascending=False).head(num_devices)
    top_devices = ord_devices[["id_dev", "vulnerabilidades"]]

    print(top_devices)
    return render_template('top_devices.html', top_devices=top_devices)

if __name__ == '__main__':
    app.run()
