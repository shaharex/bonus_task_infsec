nums = [-1 ,0, 1,2, -1, -4]
answerList = []
# for i in nums:
#     for j in nums:
#         for k in nums:
#                 if (i + j + k == 0 and nums.index(i) != nums.index(j) and nums.index(i) != nums.index(k) and nums.index(j) != nums.index(k) ):
#                     answerList.append([i, j, k])
isEqual = False
sum = 0
iter = 0
for num in nums:
    sum += num
    iter += 1

print(answerList)      