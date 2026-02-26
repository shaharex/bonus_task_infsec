def addDigits(num):
    strNum = str(num)
    sum = 0
    for i in strNum:
        sum += int(i)
    if (sum < 10 and sum > 0 or sum == 0):
        return sum
    else:
        return addDigits(sum)

print(addDigits(0))