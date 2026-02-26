ransomNote = "bg"
magazine = "efjbdfbdgfjhhaiigfhbaejahgfbbgbjagbddfgdiaigdadhcfcj"

rSlist = list(ransomNote)
mSlist = list(magazine)
sortedrs = sorted(rSlist)
sortedms = sorted(mSlist)

rs = ''
ms = ''
for i in sortedrs:
    rs += i
for i in sortedms:
    ms += i

print(rs)
print(ms)

if rs in ms:
    print("True")
else:
    print("False")

