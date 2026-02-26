def binary_search(numbers, target):
    low = 0
    high = len(numbers) - 1

    while low <= high:
        # Find the middle index
        mid = (low + high) // 2 
        
        if numbers[mid] == target:
            return mid # Found it! Return the index
        
        elif numbers[mid] < target:
            # Target is in the right half, move 'low' up
            low = mid + 1
        else:
            # Target is in the left half, move 'high' down
            high = mid - 1

    return -1 # Target not found


print(binary_search([1,2,3,4,5,6,7,8,9,10000], 100))