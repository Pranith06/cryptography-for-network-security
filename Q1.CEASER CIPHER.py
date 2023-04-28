word = input()
key = int(input())
cipher_text = ""
for i in word:
    cipher_text += chr(ord(str(i)) + key)
print(cipher_text)   
