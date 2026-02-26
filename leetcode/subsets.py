def subsets( nums):
        """
        :type nums: List[int]
        :rtype: List[List[int]]
        """
        # 
        subsets = []

        for i in range(len(nums)):
                if (i in subsets):
                        subsets.append(subsets)
                else:
                        subsets.append([i])
        return subsets

print(subsets([1,1,3]))