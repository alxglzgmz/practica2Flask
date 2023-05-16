#Ejercicio 5
import graphviz
import pandas as pd
from sklearn import tree

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


clf = tree.DecisionTreeClassifier()
clf.fit(x_training,y_training)
dot_data = tree.export_graphviz(clf, out_file=None,
                                feature_names=['Porcentaje inseguridad'],
                                class_names=['noPeligroso','peligroso'],
                                filled=True,rounded=True,special_characters=True)
graph=graphviz.Source(dot_data)
graph.render('test.gv', view=True).replace('\\','/')
