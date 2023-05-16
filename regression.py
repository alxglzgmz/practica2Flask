#Ejercicio 5
import pandas as pd
from matplotlib import pyplot as plt
from sklearn import linear_model
from sklearn.metrics import mean_squared_error

df_train = pd.read_json('devices_IA_clases (1).json')
df_test = pd.read_json('devices_IA_predecir_v2.json')

x_training = []
y_training=[]

for index, row in df_train.iterrows():
    if(row['servicios'])== 0:
        x_training.append([0])
    else:
        ratio = row['servicios_inseguros']/row['servicios']
        x_training.append([ratio])
    y_training.append([row['peligroso']])

x_test=[]
y_test=[]
for index, row in df_test.iterrows():
    if(row['servicios'])== 0:
        x_test.append([0])
    else:
        ratio = row['servicios_inseguros']/row['servicios']
        x_test.append([ratio])
    y_test.append([row['peligroso']])


regr = linear_model.LinearRegression()
regr.fit(x_training,y_training)
y_predict = regr.predict(x_test)
print("Mean squared error: %.2f" % mean_squared_error(y_test,y_predict))
plt.scatter(x_test, y_test, color="black")
plt.plot(x_test, y_predict, color="blue", linewidth=3)
plt.xticks(())
plt.yticks(())
plt.show()
plt.savefig('regresion.png')