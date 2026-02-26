nums = [1,3,5,6]
target = 7

targetIndex = 0;

def searchInsert(self, nums, target):
    for i in nums:
        if (i == target):
            return nums.index(i)
        else:
            if (target > i):
                if (nums.index(i) == len(nums) - 1):
                    return nums.index(i + 1)
                else: continue
            if (target < i):
                return nums.index(i)

