import numpy as np
import pandas as pd

columns = ['Eleanor', 'Chidi', 'Tahani', 'Jason']

my_list = []


my_data = np.random.randint(low=0, high=101, size=(3, 4))

my_dataframe = pd.DataFrame(data=my_data, columns=columns)
print(my_dataframe)


my_dataframe['Janet']  = my_dataframe['Tahani'] + my_dataframe['Jason']

print(my_dataframe)
print("Eleanor cell value")
print(my_dataframe['Janet'][1])