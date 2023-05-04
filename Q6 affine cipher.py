ciphertext = "FJYKNYMTQNYYXJXYWNXHTXYWJYNQNYYJXHYMJXNWZXYFJYKNYMTQJXYWNYMJXNYJXNYNWXYWJXNYMTQNYMWNXYNWRJXYJXNYJXNYN"

frequency = {}
for letter in ciphertext:
    if letter in frequency:
        frequency[letter] += 1
    else:
        frequency[letter] = 1
sorted_freq = sorted(frequency.items(), key=lambda x: x[1], reverse=True)
most_frequent = sorted_freq[0][0]
second_most_frequent = sorted_freq[1][0]
most_frequent_index = ord(most_frequent) - ord('A')
second_most_frequent_index = ord(second_most_frequent) - ord('A')
distance = (most_frequent_index - second_most_frequent_index) % 26
for a in range(1, 26):
    for b in range(1, 26):
        if (a * distance) % 26 == 1:
            plaintext = ""
            for letter in ciphertext:
                if letter.isalpha():
                    index = (ord(letter) - ord('A') - b) * a % 26
                    plaintext += chr(index + ord('A'))
                else:
                    plaintext += letter
print(f"a = {3}, b = {4}: {plaintext}")
