
listLength = int(input)
numList = list(map(int, input().split()))


# should choose 4 indexes that give ax + aw = az + aw
# and then print those 4 indexes

#  1. i + (i + 1) 
#  2. then write numberPairs in some list: ([1, 1] , [1,2], [1, 3], [1, 4])
#  3. write answers in some list: (2, 3, 4, 5)
#  4. compare the answers, if they are equal then take the indexes
#  for every numPairs there is answer --> if 2 answers are equal -> then we can take their indexes and compare sumIndexes
answersList = []
numbersList = []

for i in numList:
    for j in numList:
        sum = i + j
        numbersList.append([i, j])
        answersList.append(sum)

for i in answersList:
    for j in answersList:
        if (i == j):
            iIndex = answersList.index(i)
            jIndex = answersList.index(j)
            print(f"{numbersList[iIndex]} = {numbersList[jIndex]}")
            print(numbersList[iIndex] == numbersList[jIndex])


        


