def generateParenthesis(n):

    parentList = []
    if n > 0:
        for i in range(n):
            parentList.append("()")

    return parentList

print(generateParenthesis(3))