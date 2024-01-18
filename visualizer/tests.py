def length_of_longest_substring(s):
    l=0
    res = 0
    char_set = set(s)
    for r in range (len(char_set)):
        while r in char_set:
            char_set.remove(s[l])
            l+=1
        char_set.add(s[r])
        res = max(res,r-l+1)
    return res

# Example usage:
input_string = "abcabcbb"
result = length_of_longest_substring(input_string)
print(f"The length of the longest substring without repeating characters is: {result}")

