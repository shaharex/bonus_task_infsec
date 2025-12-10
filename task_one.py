import numpy as np

feature = np.arange(6, 21)
label = (3 * feature) + 4
# random_float_pos = np.random.random(len(label)) + 1
# random_float_neg = np.random.random(len(label)) - 2
noise = np.random.random(len(label)) * 4 - 2
newLabel = label + noise 
#  create the array that has the same dimension 
print(newLabel)
# print(newLabel) 

