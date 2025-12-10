# data
import numpy as np
import pandas as pd

# machine learning
import keras
# import ml_edu.experiment
# import ml_edu.results

# data 
# visualization
# import plotly.express as px


chicago_taxi_dataset = pd.read_csv("https://download.mlcc.google.com/mledu-datasets/chicago_taxi_train.csv")

training_df = chicago_taxi_dataset.loc[:, ('TRIP_MILES', 'TRIP_SECONDS', 'FARE', 'COMPANY', 'PAYMENT_TYPE', 'TIP_RATE')]


print('Read dataset completed successfully.')
print('Total number of rows: {0}\n\n'.format(len(training_df.index)))
print(training_df.describe(include='all'))