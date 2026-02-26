
def romanToInt(s):
    sList = list(s)
    print(sList)
    prevInt = ''
    num = 0
    for i in sList:
        if (i == 'I'):
            num += 1
        if (i == 'V'):
            if (prevInt == 'I'):
                num += 4
            else:
                num += 5
        if (i == 'X'):
            if (prevInt == 'I'):
                num += 9
            else:
                num += 10
        if (i == 'L'):
            if (prevInt == 'X'):
                num += 40
            else:
                num += 50
        if (i == 'C'):
            if (prevInt == 'X'):
                num += 90
            else:
                num += 100
        if (i == 'D'):
            if (prevInt == 'C'):
                num += 400
            else:
                num += 500
        if (i == 'M'):
            if (prevInt == 'C'):
                num += 900
            else:
                num += 1000
        prevInt = i

    return num


print(romanToInt('MCMXCIV'))