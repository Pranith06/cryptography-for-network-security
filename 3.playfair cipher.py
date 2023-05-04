import string
def generate_matrix(key):
    
    key = key.lower().replace("j", "i")
    alphabet = string.ascii_lowercase.replace("j", "")
    key_set = set(key)
    matrix = []
    for c in key:
        if c not in matrix:
            matrix.append(c)
    for c in alphabet:
        if c not in key_set and c not in matrix:
            matrix.append(c)
    matrix = [matrix[i:i+5] for i in range(0, 25, 5)]
    return matrix

def encrypt(plaintext, key):
   
    plaintext = plaintext.lower().replace("j", "i").replace(" ", "")
    matrix = generate_matrix(key)
    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        a = plaintext[i]
        b = plaintext[i+1] if i+1 < len(plaintext) else "x"
        if a == b:
            b = "x"
        a_row, a_col = get_position(matrix, a)
        b_row, b_col = get_position(matrix, b)
        if a_row == b_row:
            a_col = (a_col + 1) % 5
            b_col = (b_col + 1) % 5
        elif a_col == b_col:
            a_row = (a_row + 1) % 5
            b_row = (b_row + 1) % 5
        else:
            a_col, b_col = b_col, a_col
        ciphertext += matrix[a_row][a_col] + matrix[b_row][b_col]
    return ciphertext

def decrypt(ciphertext, key):
   
    matrix = generate_matrix(key)
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        a = ciphertext[i]
        b = ciphertext[i+1]
        a_row, a_col = get_position(matrix, a)
        b_row, b_col = get_position(matrix, b)
        if a_row == b_row:
            a_col = (a_col - 1) % 5
            b_col = (b_col - 1) % 5
        elif a_col == b_col:
            a_row = (a_row - 1) % 5
            b_row = (b_row - 1) % 5
        else:
            a_col, b_col = b_col, a_col
        plaintext += matrix[a_row][a_col] + matrix[b_row][b_col]
    plaintext = plaintext.replace("x", "")
    return plaintext

def get_position(matrix, letter):

    for i in range(5):
        for j in range(5):
            if matrix[i][j] == letter:
                return i, j
    return -1, -1
key = 'secretkey'
plaintext = 'hello world'
ciphertext = encrypt(plaintext, key)
print("encryption:", ciphertext)
print("decryption:", plaintext)
