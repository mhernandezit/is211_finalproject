def maxDifference(nums):
    minnumber = [0, nums[0]]
    maxnumber = [0, nums[0]]
    difference = -1
    for position, item in enumerate(nums):
        # Get the min and max of the array first
        if item <= minnumber[1]:
            print "min number: {}".format(minnumber)
            minnumber = [position, item]
        if item >= minnumber[1]:
            maxnumber = [position, item]
            print "max number: {}".format(maxnumber)
        if maxnumber[0] > minnumber[0]:
            print "max number at a higher position"
            if maxnumber[1] > minnumber[1]:
                print difference
                if maxnumber[1] - minnumber[1] > 0:
                    difference = maxnumber[1] - minnumber[1]
                    print difference
    return difference


if __name__ == "__main__":
    maxDifference([6,7,9,5,6,3,2])
