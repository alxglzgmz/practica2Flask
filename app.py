import sqlite3

import dash_table
from dash import *
from flask import *
import pandas as pd
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import dash_table
from dash import dcc
import requests
from fpdf import FPDF
from io import BytesIO
from flask import send_file
import tempfile

import plotly.express as px

server = Flask(__name__)
app = dash.Dash(external_stylesheets=[dbc.themes.UNITED], server=server, title="Dashboard SI")

conn = sqlite3.connect('practica1.db')
df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id", conn)
ord_devices = df_devices_analisis.sort_values(by='vulnerabilidades', ascending=False).head(10)
top_devices = ord_devices[["id_dev", "vulnerabilidades"]]

df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id", conn)
df_devices_analisis['porcentaje_inseguros'] = (df_devices_analisis['servicios_inseguros'] / df_devices_analisis[
    'servicios']) * 100
most_dangerous_devices = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] >= 33]
most_dangerous_devices = most_dangerous_devices[['id_dev', 'porcentaje_inseguros']]
least_dangerous_devices = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] < 33]
least_dangerous_devices = least_dangerous_devices[['id_dev', 'porcentaje_inseguros']]
fig_devices = px.bar(top_devices, x="id_dev", y="vulnerabilidades", title="Top Dispositivos Vulnerables")
fig_devices.update_xaxes(title_text="ID Dispositivo")
fig_devices.update_yaxes(title_text="Vulnerabilidades")
fig_devices.update_traces(marker_color='purple')
fig_devices.write_image("fig_devices.png")

fig_most_devices = px.bar(most_dangerous_devices, x="id_dev", y="porcentaje_inseguros",
                          title="Dispositivos más peligrosos")
fig_most_devices.update_traces(marker_color='red')
fig_most_devices.update_xaxes(title_text="ID Dispositivo")
fig_most_devices.update_yaxes(title_text="% Servicios Inseguros")
fig_most_devices.write_image("fig_most_devices.png")
fig_least_devices = px.bar(least_dangerous_devices, x="id_dev", y="porcentaje_inseguros",
                           title="Dispositivos menos peligrosos")
fig_least_devices.update_traces(marker_color='green')
fig_least_devices.update_xaxes(title_text="ID Dispositivo")
fig_least_devices.update_yaxes(title_text="% Servicios Inseguros")
fig_least_devices.write_image("fig_least_devices.png")

top_devices = top_devices.set_index('id_dev')

top_ips = df_alerts['origen'].value_counts().head(10)
ips_bar = go.Bar(x=top_ips.index, y=top_ips.values)

response = requests.get('https://cve.circl.lu/api/last')
df_cve = pd.read_json(response.text)
df_cve = df_cve.head(10)
df_cve = df_cve[['Published', 'id']]

print(top_ips.reset_index().to_dict('records'))

table_ips = dash_table.DataTable(
    data=top_ips.reset_index().to_dict('records'),
    columns=[{"name": 'IPs Origen', "id": 'index'}, {'name': 'Apariciones', 'id': 'origen'}],

    style_cell={
        'textAlign': 'left',
        'minWidth': '0px',
    },
    style_table={
        'maxWidth': '400px', 'border': '1px solid black'
    },
    style_header={
        'fontWeight': 'bold',
        'fontSize': '20px'
    }
)
table_devices = dash_table.DataTable(
    data=top_devices.reset_index().to_dict('records'),
    columns=[{"name": 'ID Dispositivo', "id": 'id_dev'}, {'name': 'Nº Vulnerabilidades', 'id': 'vulnerabilidades'}],
    style_cell={
        'textAlign': 'left',
        'minWidth': '0px',
    },
    style_table={
        'maxWidth': '400px', 'border': '1px solid black'
    },
    style_header={
        'fontWeight': 'bold',
        'fontSize': '20px'
    }
)

table_cve = dash_table.DataTable(
    data=df_cve.to_dict('records'),
    columns=[{"name": 'ID del CVE', "id": 'id'}, {'name': 'Publicado', 'id': 'Published'}],
    style_cell={
        'textAlign': 'left',
        'minWidth': '0px',
    },
    style_table={
        'maxWidth': '400px', 'border': '1px solid black'
    },
    style_header={
        'fontWeight': 'bold',
        'fontSize': '20px'
    }
)

# Define el layout de la aplicación


# app.layout = dbc.Container(children=[
#     html.H1(children='Mi Dashboard'),
#     html.Br(),
#     html.Br(),
#     html.H1(children='''
#         Top 10 direcciones IP
#     '''),
#     html.Div([
#         table_ips,
#         html.Br(),
#         dcc.Graph(
#             id='graph',
#             figure={
#                 'data': [ips_bar],
#                 'layout': {
#                     'title': 'Top 10 Direcciones IP Origen',
#                     'xaxis': {'title': 'Direcciones IP'},
#                     'yaxis': {'title': 'Apariciones'}
#                 }
#             }
#         ),], style={'padding': '10px'}),
#     html.H1(children='''
#         Top dispositivos más vulnerables
#     '''),
#     html.Div([
#         table_devices,
#         html.Br(),
#         dcc.Graph(
#             id='graph2',
#             figure=fig_devices
#
#         ),], style={'padding':'10 px'}),
#     html.H1(children='''
#         Top dispositivos peligrosos
#     '''),
#     html.Br(),
#     html.H2(children='''
#         Elija una opción:
#     '''),
#
#     dcc.RadioItems(options=['Dispositivos más peligrosos','Dispositivos menos peligrosos'],value='Dispositivos más peligrosos', id='controls-and-radio-item'),
#     html.Br(),
#     html.H2(children='''
#         Tabla de la opción elegida:
#     '''),
#     html.Br(),
#     html.Div(id='tabla'),
#     html.Br(),
#     html.H2(children='''
#         Gráfico de la opción elegida:
#     '''),
#     html.Br(),
#     html.Div(id='grafico'),
#     html.Br(),
#     html.H1(children='''
#         Últimas 10 CVEs descubiertas
#     '''),
#     html.Br(),
#     table_cve
# ])

app.layout = html.Div([
    dbc.NavbarSimple(
        children=[
            dbc.NavItem(dbc.NavLink("Inicio", href="#")),

        ],
        brand="CMI",
        color="primary",
        dark=True
    ),
    dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(
                        html.H1("Dashboard SI", className="text-center"),

                    ),
                    html.Br()
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(
                        html.Div([
                            html.H2("Top 10 IPs Origen más Problemáticas"),
                            table_ips,
                            dcc.Graph(
                                id='graph',
                                figure={
                                    'data': [ips_bar],
                                    'layout': {
                                        'title': 'Top 10 Direcciones IP Origen',
                                        'xaxis': {'title': 'Direcciones IP'},
                                        'yaxis': {'title': 'Apariciones'}
                                    }
                                }
                            )

                        ])
                    ),
                    dbc.Col(
                        html.Div([
                            html.H2("Top dispositivos más vulnerables"),
                            table_devices,
                            dcc.Graph(
                                id='graph2',
                                figure=fig_devices

                            )

                        ])
                    )
                ]
            ),
            html.Br(),
            dbc.Row([

                html.H2("Top dispositivos inseguros"),
                html.H3("Elija una opción:"),
                dcc.RadioItems(options=['Dispositivos más peligrosos', 'Dispositivos menos peligrosos'],
                               value='Dispositivos más peligrosos', id='controls-and-radio-item',
                               labelStyle={'display': 'block'},
                               inputClassName='form-check-input',
                               labelClassName='form-check-label')

            ]),
            html.Br(),
            dbc.Row([
                html.Br(),
                html.Div(id="tabla"),
                html.Div(id="grafico")
            ]),
            html.Br(),

            dbc.Row([
                html.H2("Último 10 CVEs añadidos"),
                html.Br(),
                table_cve

            ]),
            html.Br(),

            dbc.Row([
                html.H2("Generar informe"),
                dbc.Button("Generar Informe", id="boton-generar-informe", color="primary", className="mr-1"),
                html.Div(id="informe")

            ])

        ],
        className="mt-4"
    )
])


@callback(
    Output('tabla', 'children'),
    Input(component_id='controls-and-radio-item', component_property='value')
)
def update_table(value):
    if value == 'Dispositivos más peligrosos':

        return dash_table.DataTable(
            id='table1',
            data=most_dangerous_devices.to_dict('records'),
            columns=[{"name": 'ID Dispositivo', "id": 'id_dev'}, {'name': '% Inseguros', 'id': 'porcentaje_inseguros'}],
            style_cell={
                'textAlign': 'left',
                'minWidth': '0px',
            },
            style_table={
                'maxWidth': '400px', 'border': '1px solid black'
            },
            style_header={
                'fontWeight': 'bold',
                'fontSize': '20px'
            }
        )
    else:

        return dash_table.DataTable(
            id='table1',
            data=least_dangerous_devices.to_dict('records'),
            columns=[{"name": 'ID Dispositivo', "id": 'id_dev'}, {'name': '% Inseguros', 'id': 'porcentaje_inseguros'}],
            style_cell={
                'textAlign': 'left',
                'minWidth': '0px',
            },
            style_table={
                'maxWidth': '400px', 'border': '1px solid black'
            },
            style_header={
                'fontWeight': 'bold',
                'fontSize': '20px'
            }
        )


@callback(
    Output('grafico', 'children'),
    Input(component_id='controls-and-radio-item', component_property='value')
)
def update_graph(value):
    if value == 'Dispositivos más peligrosos':
        return dcc.Graph(
            id='grafico1',
            figure=fig_most_devices)
    else:
        return dcc.Graph(
            id='grafico2',
            figure=fig_least_devices
        )


@callback(
    Output('informe', 'children'),
    Input(component_id='boton-generar-informe', component_property='n_clicks')
)
def generar_informe(n_clicks):
    if n_clicks:
        # Crear documento PDF
        pdf = FPDF()
        pdf.add_page()

        # Agregar título y subtítulo
        pdf.set_font("Arial", size=16)
        pdf.cell(200, 10, txt="Informe de Vulnerabilidades", ln=1, align="C")
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Generado automáticamente por Dashboard SI", ln=1, align="C")

        # Agregar gráficos y tablas
        pdf.cell(200, 10, txt="Top Dispositivos Vulnerables", ln=1)
        pdf.image("fig_devices.png", x=10, y=40, w=100)
        pdf.cell(200, 10, txt="Dispositivos más peligrosos", ln=1)
        pdf.image("fig_most_devices.png", x=10, y=100, w=100)
        pdf.cell(200, 10, txt="Dispositivos menos peligrosos", ln=1)
        pdf.image("fig_least_devices.png", x=10, y=160, w=100)
        pdf.cell(200, 10, txt="Top 10 Direcciones IP Origen", ln=1)
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt=top_ips.to_frame().to_string(index=False), ln=1)
        pdf.cell(200, 10, txt="Top 10 CVEs más recientes", ln=1)
        pdf.cell(200, 10, txt=df_cve.to_string(index=False), ln=1)

        # Crear documento PDF
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            pdf.output(tmp.name)

        # Enviar archivo como respuesta
        return send_file(tmp.name, as_attachment=True)


# @app.route('/')
# def main():  # put application's code here
#
#     conn = sqlite3.connect('practica1.db')
#     df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
#
#     top_ips = df_alerts['origen'].value_counts().head(10)
#     return render_template('top_ips.html', top_ips=top_ips)
#     return 'Hello World!'
#
#
# @app.route('/ips/<int:num_ips>')
# def top_ips(num_ips):
#     conn = sqlite3.connect('practica1.db')
#     df_alerts = pd.read_sql_query("SELECT * FROM alerts",conn)
#
#     top_ips = df_alerts['origen'].value_counts().head(num_ips)
#     return render_template('top_ips.html', top_ips=top_ips)
#
# @app.route('/devices/<int:num_devices>')
# def top_devices(num_devices):
#     conn = sqlite3.connect('practica1.db')
#     df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id",conn)
#
#     ord_devices = df_devices_analisis.sort_values(by='vulnerabilidades', ascending=False).head(num_devices)
#     top_devices = ord_devices[["id_dev", "vulnerabilidades"]]
#
#     print(top_devices)
#     return render_template('top_devices.html', top_devices=top_devices)
#


if __name__ == '__main__':
    app.run_server(debug=True)
#
#
# @app.route('/dangerousDevices/<int:x>', methods=['GET','POST'])
# def danger_devices(x):
#
#     option = request.args.get('option')
#     conn = sqlite3.connect('practica1.db')
#     df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id",conn)
#
#     df_devices_analisis['porcentaje_inseguros'] = (df_devices_analisis['servicios_inseguros']/df_devices_analisis['servicios']) * 100
#
#     # Filtrar dispositivos peligrosos según la opción seleccionada
#     if option == 'menos_inseguros':
#         dangerous_df = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] < 33]
#     else:
#         dangerous_df = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] >= 33]
#
#     top_x = dangerous_df.sort_values('porcentaje_inseguros').head(x)
#     return render_template('dangerous_devices.html', x=x, option=option, top_x=top_x)
#
#
