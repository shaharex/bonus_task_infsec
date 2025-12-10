import numpy as np
import pandas as pd



# my_data = np.array([[0,3], [10,7], [20,9], [30,14], [40,15]])

# my_column_names = ['temperature', 'activity']

# my_dataframe = pd.DataFrame(data=my_data, columns=my_column_names)
# my_dataframe["ajusted"] = my_dataframe['activity'] + 2

# print(my_dataframe, '\n')

# print("Rows #0, #1 and #2:")
# print(my_dataframe.head(3), '\n')

# print("Rows #2:")
# print(my_dataframe.iloc[[2]], '\n')

# print("Rows #1, #2 and #3")
# print(my_dataframe[1:4], '\n')

# print("Column temperature")
# print(my_dataframe["temperature"], '\n')

# creating reference
# change in the original dataframe will affect the change in the reference
reference_to_df = my_dataframe

print(f"initial value of my_df: {my_dataframe['activity'].iloc[[1]]}\n")
print(f"initial value of reference: {reference_to_df['activity'].iloc[[1]]}\n")

my_dataframe.at[1, 'activity'] = my_dataframe['activity'][1] + 5
print(f"updated my_df: {my_dataframe['activity'].iloc[[1]]}\n")
print(f"updated reference: {reference_to_df['activity'].iloc[[1]]}\n")

# copy of the df
copy_of_dataframe = my_dataframe.copy()

print(f"initial value of my_df: {my_dataframe['activity'].iloc[[1]]}\n")
print(f"initial value of copy: {copy_of_dataframe['activity'].iloc[[1]]}\n")

my_dataframe.at[1, 'activity'] = my_dataframe['activity'][1] + 3
print(f"updated my_df: {my_dataframe['activity'].iloc[[1]]}\n")
print(f"updated copy: {copy_of_dataframe['activity'].iloc[[1]]}\n")

