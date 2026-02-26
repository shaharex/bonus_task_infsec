def findMedianSortedArrays( nums1, nums2):
        """
        :type nums1: List[int]
        :type nums2: List[int]
        :rtype: float
        """
        nums1Sum = 0
        nums2Sum = 0
        for i in nums1:
            nums1Sum += i

        for i in nums2:
            nums2Sum += i
    
        nums1Med = nums1Sum / len(nums1)
        print(nums1Med)
        nums2Med = nums2Sum / len(nums2)
        print(nums2Med)


        numsMed = (nums1Med + nums2Med) / 2
        return numsMed

print(findMedianSortedArrays([1,2], [3, 4]))