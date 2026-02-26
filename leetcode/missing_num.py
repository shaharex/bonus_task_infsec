
#  balanced if max(nums) <= min * k
# find out how many nums should we remove so the array is balanced
# 
def missingNum(nums):
        """
        :type nums: List[int]
        :type k: int
        :rtype: int
        """
        # sum all numbers from 1 to 3
        # sum all numbers in nums
        # how to find is the list allEqual or not
        numsSorted = sorted(nums)
        maxNum = max(nums) + 1
        allEqual = True
        for i in range(maxNum):
                if (i == numsSorted[i]):
                        allEqual = True
                        continue
                else:
                        return i
        if (allEqual):
                return maxNum
                
       
                

print(missingNum([1, 2]))