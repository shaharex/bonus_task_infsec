s = "Hello World"
splittedS = s.split(' ')
sList = splittedS[::-1]
for i in sList:
    if len(i) != 0:
        print(len(i))
        break
    else:
        continue

# for i in splittedS:
#     if len(i) == 0:
#         splittedS.remove(i)
#     else:
#         continue
# print(splittedS)