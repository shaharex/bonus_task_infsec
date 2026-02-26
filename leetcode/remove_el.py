def removeElement(nums, val):
    """
    :type nums: List[int]
    :type val: int
    :rtype: int
    """
    for i in nums:
        if (i == val):
            nums.remove(i)
    
    

        
removeElement([0,1,2,2,3,0,4,2], 2)