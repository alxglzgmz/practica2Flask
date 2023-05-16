import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn import datasets, linear_model
from sklearn.ensemble import RandomForestClassifier
from subprocess import call
import json

from sklearn.metrics import mean_squared_error
from sklearn.tree import export_graphviz

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


clf = RandomForestClassifier(max_depth=2, random_state=0,n_estimators=10)
clf.fit(x_training,y_training)

for i in range(len(clf.estimators_)):
    print(i)
    estimator = clf.estimators_[i]
    export_graphviz(estimator,
                    out_file='tree.dot',
                    feature_names=['Porcentaje de inseguridad'],
                    class_names=['noPeligroso','peligroso',],
                    rounded=True, proportion=False,
                    precision=2, filled=True)
    call(['dot', '-Tpng', 'tree.dot', '-o', 'tree'+str(i)+'.png', '-Gdpi=600'])


y_predict = clf.predict(x_test)
print("Mean squared error: %.2f" % mean_squared_error(y_test, y_predict))