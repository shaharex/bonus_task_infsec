def reverseBits(n):
        """
        :type n: int
        :rtype: int
        """
        binFormat = format(n, '032b')
        binReverse = binFormat[::-1]

        return int(binReverse, 2);

reverseBits(43261596)