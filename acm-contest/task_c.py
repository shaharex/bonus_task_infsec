homBox = list(map(int, input().split()))
boxTypes = list(map(int, input().split()))

# 1. 19 / 10 = 1 remainder 9
# 2. 19 / 4 = 4 remainder 3
# 3. 19 / 5 = 3 remainder 4
# answer: 2 4
# save the i with the lowest remainder
# the best option is 2, then compare remainders -> which one is smaller that is the answer

remaindersList = [] 
boxList = [] 
for i in boxTypes:
    remaind = homBox[0] % i
    boxNum = homBox[0] // i
    remaindersList.append(remaind)
    boxList.append(boxNum)
    

minNum = min(remaindersList)
indexOfBox = remaindersList.index(minNum)
print(f"{indexOfBox + 1} {boxList[indexOfBox]}")




    