


def reverse(x):
    t1Length = x.bit_length()

    if (t1Length <= 32):
        sign = -1 if x < 0 else 1
        num = abs(x)
        reversed_num = 0

        while num != 0:
            digit = num % 10          
            reversed_num = reversed_num * 10 + digit
            num //= 10

        finalNum = reversed_num * sign 
        if (finalNum.bit_length() < 32):
            return finalNum
        else:
            return 0
    else:
        return 0


print(reverse(1563847412))