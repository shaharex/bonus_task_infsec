nm = list(map(int, input().split()))
songsList = []
for i in range(nm[0]):
    songsList.append(list(map(int, input().split())))
 



# first add all songs without zipping them, if ok then print 0
# then try to add the zipped size one by one, if it's < than m, then print the num of zipped songs
# repeat this till we find the num of zipped songs, if not then print -1
# 1. 10 + 7 + 3 + 5 = 25 <= 21
# 2. 8 + 7 + 3 + 5 = 23 <= 21
# 3. 8 + 4 + 3 + 5 = 20 <= 21

# find the space that we need, if it's 4 then 10 - 8 = 2

songsSizeNotZipped = 0
songsSizeZipped = 0
spaceWeNeed = 0
for i in songsList:
        songsSizeNotZipped += i[0]
        songsSizeZipped += i[1]
        spaceWeNeed = songsSizeNotZipped - nm[1]

if (songsSizeZipped > nm[1]):
      print(-1)
else:
    if (spaceWeNeed == 0):
        print(0)
    if (spaceWeNeed > 0):
        songsCount = 0;
        sumOfspace = 0;
        for i in songsList:
                sumOfspace += (i[0] - i[1])
                songsCount +=1
                if (sumOfspace > spaceWeNeed):
                        print(songsCount)
                        break
