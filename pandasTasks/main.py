import pandas as pd
import statistics as st
import numpy as np

# df=pd.DataFrame({"Alem": [98, 87, 76, 88, 96], "Bakyt": [88, 52, 69, 79, 82], "Asyl": [90, 92, 71, 60, 64]})

# print(df.var(ddof=0))


# summa = df['Alem'].sum()
# count = 0
# n = len(df['Alem']);
# for i in range(n):
#     count += df['Alem'][i]**2

# df.std(ddof=1)
# print(1/(n-1) * (count - summa**2/n))
# print(np.sqrt(1/(n-1) * (count - summa**2/n)))

ex = [21, 15, 9, 17, 23, 2]
print(st.mean(ex))
print(st.variance(ex))
print(np.sqrt(st.variance(ex)))