import sqlite3

import VirusTotalApi3.utils
import dash_table
import graphviz
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
import tempfile
import json
import os
from flask import send_file, make_response
#from informe import app as informe_app
#from informe import generar_informe
from flask import Flask, send_file, url_for

import plotly.express as px
from matplotlib import pyplot as plt
from sklearn import linear_model, tree
from sklearn.metrics import mean_squared_error

server = Flask(__name__)
app = dash.Dash(external_stylesheets=[dbc.themes.UNITED], server=server, title="Dashboard SI")

#TRATAMIENTO DE DATAFRAMES
conn = sqlite3.connect('practica1.db')
df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id", conn)
ord_devices = df_devices_analisis.sort_values(by='vulnerabilidades', ascending=False).head(10)
top_devices = ord_devices[["id_dev", "vulnerabilidades"]]
df_devices_analisis = pd.read_sql_query("SELECT * FROM devices JOIN analisis on devices.analisis_id=analisis.id", conn)
df_devices_analisis['porcentaje_inseguros'] = (df_devices_analisis['servicios_inseguros'] / df_devices_analisis['servicios']) * 100
most_dangerous_devices = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] >= 33]
most_dangerous_devices = most_dangerous_devices[['id_dev', 'porcentaje_inseguros']]
least_dangerous_devices = df_devices_analisis[df_devices_analisis['porcentaje_inseguros'] < 33]
least_dangerous_devices = least_dangerous_devices[['id_dev', 'porcentaje_inseguros']]


#TRATAMIENTO DE GRÁFICOS E IMÁGENES
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

#PETICION A LA API DE CVE
response = requests.get('https://cve.circl.lu/api/last')
df_cve = pd.read_json(response.text)
df_cve = df_cve.head(10)
df_cve = df_cve[['Published', 'id']]


# PETICION A LA API DE VIRUSTOTAL
url=f'https://www.virustotal.com/api/v3/popular_threat_categories'
headers = {'x-apikey':'7ae26c7cf98a49cc47563a714f9d9c0683e8c1a1e21091ec85987f5ac0ce3607'}
response1 = requests.get(url,headers=headers)
response1json = response1.json()
df_threat = pd.DataFrame.from_dict(response1json)


# CREACION DE TABLAS DATATABLE PARA EL DASHBOARD
table_threats = dash_table.DataTable(
    data=df_threat.reset_index().to_dict('records'),
    columns=[{"name": 'Amenazas', "id": 'data'}],
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

#DISTRIBUCION DEL DASHBOARD
dummy_div = html.Div(id="dummy-div")
app.layout = html.Div([
    dbc.NavbarSimple(
        children=[

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
                        #EJERCICIO 1
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
                        #EJERCICIO 1
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
                #EJERCICIO 2
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
                dbc.Col(
                    #EJERCICIO 3
                    html.Div([
                            html.H2("Último 10 CVEs añadidos"),
                            html.Br(),
                            table_cve,

                        ])

                ),

                dbc.Col(
                    html.Div([
                        #EJERCICIO 4
                            html.H2("Top amenazas según VirusTotal API"),
                            table_threats,

                        ])

                )

            ]),

            html.Br(),
            dbc.Row([

                html.Button("Generar informe", id="generar-informe-button", className="mr-2"),
                dummy_div,
                html.A("Descargar informe", id="download-pdf", download="informe.pdf", href="/download/informe.pdf", target="_blank")

            ])

        ],
        className="mt-4"
    )
])

#CONTROL DE BOTONES DE RADIO
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


#INFORME EJERCICIO 4
def generar_informe_pdf():
    pdf = FPDF()
    pdf.add_page()


    # Agregar título y subtítulo
    pdf.set_font("Arial", size=16)
    pdf.cell(200, 10, txt="Informe de Dispositivos", ln=1, align="C")
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Generado automáticamente por Dashboard SI", ln=1, align="C")

    # Dispositivos menos peligrosos
    pdf.cell(200, 10, txt="Dispositivos menos peligrosos", ln=1)
    pdf.image("fig_least_devices.png", x=10, y=pdf.get_y(), w=100)  # Imagen debajo del texto
    pdf.cell(200, 70, txt="", ln=1)  # Espacio en blanco después de la imagen

    # Dispositivos más peligrosos
    pdf.cell(200, 10, txt="Dispositivos más peligrosos", ln=1)
    pdf.cell(200, 10, txt="", ln=1)
    pdf.image("fig_most_devices.png", x=10, y=pdf.get_y(), w=100)
    pdf.cell(200, 70, txt="", ln=1)

    # Top Dispositivos vulnerables
    pdf.cell(200, 10, txt="Top Dispositivos vulnerables", ln=1)
    pdf.cell(200, 10, txt="", ln=1)
    pdf.image("fig_devices.png", x=10, y=pdf.get_y(), w=100)
    pdf.cell(200, 10, txt="", ln=1)

    pdf.output("informe.pdf")


@app.server.route("/download/informe.pdf")
def download_informe():
    """Genera y descarga el informe en formato PDF"""
    generar_informe_pdf()  # Generar el informe PDF

    # Leer el contenido del archivo PDF
    with open("informe.pdf", "rb") as f:
        pdf_content = f.read()

    # Crear una respuesta para descargar el archivo
    response = make_response(pdf_content)
    response.headers["Content-Disposition"] = "attachment; filename=informe.pdf"
    response.headers["Content-Type"] = "application/pdf"

    return response


@app.callback(
    Output("dummy-div", "children"),
    Input("generar-informe-button", "n_clicks")
)
def generar_informe(n_clicks):
    if n_clicks is not None and n_clicks > 0:
        generar_informe_pdf()
        return "Informe generado correctamente, pulse el boton de Descargar Informe"
    else:
        return ""


# #Ejercicio 5
#
# df_train = pd.read_json('devices_IA_clases (1).json')
# df_test = pd.read_json('devices_IA_predecir_v2.json')
#
# x_training = []
# y_training=[]
#
# for index, row in df_train.iterrows():
#     if(row['servicios'])== 0:
#         x_training.append([0])
#     else:
#         ratio = row['servicios_inseguros']/row['servicios']
#         x_training.append([ratio])
#     y_training.append([row['peligroso']])
#
# x_test=[]
# y_test=[]
# for index, row in df_test.iterrows():
#     if(row['servicios'])== 0:
#         x_test.append([0])
#     else:
#         ratio = row['servicios_inseguros']/row['servicios']
#         x_test.append([ratio])
#     y_test.append([row['peligroso']])
#
#
# regr = linear_model.LinearRegression()
# regr.fit(x_training,y_training)
# y_predict = regr.predict(x_test)
# print("Mean squared error: %.2f" % mean_squared_error(y_test,y_predict))
# plt.scatter(x_test, y_test, color="black")
# plt.plot(x_test, y_predict, color="blue", linewidth=3)
# plt.xticks(())
# plt.yticks(())
# plt.show()
# plt.savefig('regresion.png')


# clf = tree.DecisionTreeClassifier()
# clf.fit(x_training,y_training)
# dot_data = tree.export_graphviz(clf, out_file=None,
#                                 feature_names=['Porcentaje inseguridad'],
#                                 class_names=['peligroso','noPeligroso'],
#                                 filled=True,rounded=True,special_characters=True)
# graph=graphviz.Source(dot_data)
# graph.render('test.gv', view=True).replace('\\','/')






if __name__ == '__main__':
    app.run_server(debug=True)
