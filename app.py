import sqlite3


from flask import *
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


@app.route('/dangerousDevices/<int:x>', methods=['GET','POST'])
def danger_devices(x):

    option = request.args.get('option')
    conn = sqlite3.connect('practica1.db')
    df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id",conn)

    df_devices_analisis['porcentaje_inseguros'] = (df_devices_analisis['servicios_inseguros']/df_devices_analisis['servicios']) * 100

    # Filtrar dispositivos peligrosos según la opción seleccionada
    if option == 'menos_inseguros':
        dangerous_df = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] < 33]
    else:
        dangerous_df = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] >= 33]

    top_x = dangerous_df.sort_values('porcentaje_inseguros').head(x)
    return render_template('dangerous_devices.html', x=x, option=option, top_x=top_x)


