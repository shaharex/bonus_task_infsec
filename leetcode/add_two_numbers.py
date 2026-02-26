l1 = [2, 4, 3]
l2 = [5, 6, 4]


reversedL1 = l1[::-1]
reversedL2 = l2[::-1]
l1Num = '';
for i in reversedL1:
    l1Num += str(i)
l2Num = '';
for i in reversedL2:
    l2Num += str(i)


sumOfls = int(l1Num) + int(l2Num)

resultArray = []
for char in str(sumOfls):
    resultArray.append(int(char))

print(resultArray[::-1])