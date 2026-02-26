letters = ["c","f","j"]
target = "a"

s = 'abcdefghijklmnopqrstuvwxyz'
sList = list(s)

indexOfTar = s.index(target) 
smallerThan = 0
prevIndex = 0
for i in letters:
    indexOfi = s.index(i) 
    if (indexOfi > indexOfTar):
        smallerThan = indexOfi
    
    if (prevIndex > indexOfi):
        prevIndex = indexOfi

print(prevIndex)

    
