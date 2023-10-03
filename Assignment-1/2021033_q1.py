sbox = [
    ['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'],
    ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'F0', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'C0'],
    ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'],
    ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'],
    ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
    ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'],
    ['D0', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'],
    ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'],
    ['CD', '0C', '13', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'],
    ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', '0B', 'DB'],
    ['E0', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'],
    ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'],
    ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'],
    ['70', '3E', 'B5', '66', '48', '03', 'F6', '0E', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'],
    ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'],
    ['8C', 'A1', '89', '0D', 'BF', 'E6', '42', '68', '41', '99', '2D', '0F', 'B0', '54', 'BB', '16']
]

inverse_sbox = [[0] * 16 for _ in range(16)]

d = {}

for x, row in enumerate(sbox):
    for y, j in enumerate(row):
        hex_x = str(hex(x).split('x')[-1]).upper()
        hex_y = str(hex(y).split('x')[-1]).upper()
        d[j] = hex_x + hex_y

# For every value in the S-box, the dictionary d will map the value to its position in hexadecimal format.
# The position is a combination of the row and column indices.

for i in range(16):
    for j in range(16):
        m, n = sbox[i][j][0], sbox[i][j][1]
        x = int(m,16)
        y = int(n,16)
        inverse_sbox[x][y] = d[sbox[i][j]]

# creation of the inverse sbox matrix

def hexadecimal_notation(x):
    temp = ord(x)
    ans = str(hex(temp)).split('x')
    if(len(ans[1]) != 2):
        ans[1] = '0'+ans[1]
    return ans[1].upper()
# used for the conversion of the message to hexadecimal notation

def xor(x,y):
    result = []
    for i in range(4):
        temp = str(hex(int(x[i],16)^int(y[i],16)).split('x')[-1]).upper()
        if(len(temp) != 2):
            temp = '0'+temp

        result.append(temp)
    return result

def rotWord(word):
    result = []
    result.extend(word[1:])
    result.append(word[0])
    return result

def subWord(word):
    result = []
    for byte in word:
        row = int(byte[0], 16)
        col = int(byte[1], 16)
        substituted_byte = sbox[row][col]
        result.append(substituted_byte)
    return result


def convert_key_to_hex_list(key):
    hex_list = []
    for char in key:
        hex_representation = hexadecimal_notation(char)
        hex_list.append(hex_representation)
    return hex_list

def gf256_multiply_by_2(a):
    result = a << 1
    if result & 0x100:
        result ^= 0x11b  
    return result & 0xff

def generate_rcon(num_values):
    rcon = ['01']
    current_value = 0x01
    
    for _ in range(num_values - 1):
        current_value = gf256_multiply_by_2(current_value)
        rcon.append(format(current_value, '02X'))
    
    return rcon

# function to generate the rcon values for the key expansion function 

def key_expansion(key):
    hexed_key = convert_key_to_hex_list(key)
    roundKey = []
    roundKey.append(hexed_key)
    rc = generate_rcon(10)
    # print(rc)

    for i in range(10):
        temp = rotWord(roundKey[-1][12:16])
        subtituted = subWord(temp)
        
        first_byte_as_int = int(subtituted[0], 16)
        rc_as_int = int(rc[i], 16)
        xor_result = first_byte_as_int ^ rc_as_int
        
        subtituted[0] = '{:02X}'.format(xor_result)
        
        w4 = xor(roundKey[-1][0:4], subtituted)
        w5 = xor(roundKey[-1][4:8], w4)
        w6 = xor(roundKey[-1][8:12], w5)
        w7 = xor(roundKey[-1][12:16], w6)

        w_final = []
        w_final.extend(w4)
        w_final.extend(w5)
        w_final.extend(w6)
        w_final.extend(w7)

        roundKey.append(w_final)

    return roundKey

# function to generate the round keys for the key expansion function 

def xor_hex_values(hex_val1, hex_val2):
    xor_result = int(hex_val1, 16) ^ int(hex_val2, 16)
    formatted_hex_result = '{:02X}'.format(xor_result)
    return formatted_hex_result

# function to perform the xor operation on the hex values

def XOR_matrix(x, y):
    
    result_matrix = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]
    
    for row in range(4):
        for col in range(4):
            hex_value_1 = x[row][col]
            hex_value_2 = y[row][col]
            
            xor_result = xor_hex_values(hex_value_1, hex_value_2)
            
            result_matrix[row][col] = xor_result

    return result_matrix

# function to perform the xor operation on the matrix 

def sub_bytes(substitution_matrix):
    for row in range(4):
        for col in range(4):
            m = int(substitution_matrix[row][col][0], 16)
            n = int(substitution_matrix[row][col][1], 16)
            substitution_matrix[row][col] = sbox[m][n]
    return substitution_matrix

# function to perform the substitution operation on the matrix

def inverse_sub_bytes(state_matrix):
    for j in range(4):
        for k in range(4):
            m = int(state_matrix[j][k][0], 16)
            n = int(state_matrix[j][k][1], 16)
            state_matrix[j][k] = inverse_sbox[m][n]
    return state_matrix

# function to perform the inverse substitution operation on the matrix

def shift_rows(state_matrix):
    temp = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]
    
    for j in range(4):
        for k in range(4):
            temp[j][k] = state_matrix[j][k]

    for j in range(4):
        for k in range(4):
            state_matrix[j][k] = temp[j][(k+j)%4]
    return state_matrix

# function to perform the shift rows operation on the matrix

def inverse_shift_rows(state_matrix):
    temp = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]
    
    for j in range(4):
        for k in range(4):
            temp[j][k] = state_matrix[j][k]
    
    for j in range(4):
        for k in range(4):
            state_matrix[j][k] = temp[j][(4 + k - j) % 4]
    return state_matrix

# function to perform the inverse shift rows operation on the matrix



def galois_multiply(a, b):
    p = 0
    for counter in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p % 256

def mix_columns(state):
    fixed_matrix = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]
    
    new_state = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = int(state[i][j], 16)
    
    for r in range(4):
        for c in range(4):
            new_state[r][c] = galois_multiply(fixed_matrix[r][0], state[0][c]) ^ \
                              galois_multiply(fixed_matrix[r][1], state[1][c]) ^ \
                              galois_multiply(fixed_matrix[r][2], state[2][c]) ^ \
                              galois_multiply(fixed_matrix[r][3], state[3][c])
    for i in range(4):
        for j in range(4):
            new_state[i][j] = hex(new_state[i][j]).split('x')[-1].upper()
            if(len(new_state[i][j]) != 2):
                new_state[i][j] = '0'+new_state[i][j]
            
    return new_state

def inverse_mix_columns(state):
    inverse_fixed_matrix = [
        [14, 11, 13, 9],
        [9, 14, 11, 13],
        [13, 9, 14, 11],
        [11, 13, 9, 14]
    ]
    # convert the state matrix to integer matrix

    for i in range(4):
        for j in range(4):
            state[i][j] = int(state[i][j], 16)


    new_state = [[0]*4 for _ in range(4)]
    
    for r in range(4):
        for c in range(4):
            new_state[r][c] = galois_multiply(inverse_fixed_matrix[r][0], state[0][c]) ^ \
                              galois_multiply(inverse_fixed_matrix[r][1], state[1][c]) ^ \
                              galois_multiply(inverse_fixed_matrix[r][2], state[2][c]) ^ \
                              galois_multiply(inverse_fixed_matrix[r][3], state[3][c])
    
    # convert new state matrix to hex matrix
    for i in range(4):
        for j in range(4):
            new_state[i][j] = hex(new_state[i][j]).split('x')[-1].upper()
            if(len(new_state[i][j]) != 2):
                new_state[i][j] = '0'+new_state[i][j]
            
    return new_state

# function to perform the multiplication operation on the matrix

def add_round_key(state, round_key):
    key_matrix = [
        [round_key[0], round_key[4], round_key[8], round_key[12]],
        [round_key[1], round_key[5], round_key[9], round_key[13]],
        [round_key[2], round_key[6], round_key[10], round_key[14]],
        [round_key[3], round_key[7], round_key[11], round_key[15]],
    ]
    # print("Kehy matreix here:l ",key_matrix)
    return XOR_matrix(state, key_matrix)

#  function to perform the add round key operation on the matrix

def encrypt(msg, roundKey):
    msg_list = list(msg)
    msg_list1 = [hexadecimal_notation(i) for i in msg_list]
    state_matrix = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]
    temp_key = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]
    k = 0
    for col in range(4):
        for row in range(4):
            state_matrix[row][col] = msg_list1[k]
            temp_key[row][col] = roundKey[0][k]
            k += 1
    state_matrix = XOR_matrix(state_matrix, temp_key)
    for i in range(10):
        state_matrix = sub_bytes(state_matrix)
        state_matrix = shift_rows(state_matrix)
        if i != 9:  
            state_matrix = mix_columns(state_matrix)
        state_matrix = add_round_key(state_matrix, roundKey[i+1])
        # print("Round ",i+1,": ",state_matrix)
    cipherText = ""
    for col in range(4):
        for row in range(4):
            cipherText += state_matrix[row][col]

    return cipherText

# function to perform the encryption operation on the matrix

def add_round_key2(state_matrix, roundKey, i):
    z = [
        [roundKey[i+1][0], roundKey[i+1][4], roundKey[i+1][8], roundKey[i+1][12]],
        [roundKey[i+1][1], roundKey[i+1][5], roundKey[i+1][9], roundKey[i+1][13]],
        [roundKey[i+1][2], roundKey[i+1][6], roundKey[i+1][10], roundKey[i+1][14]],
        [roundKey[i+1][3], roundKey[i+1][7], roundKey[i+1][11], roundKey[i+1][15]],
    ]
    return XOR_matrix(state_matrix, z)

def state_matrix_to_text(state_matrix):
    plainText_list = list()

    for i in range(4):
        for j in range(4):
            plainText_list.append(state_matrix[j][i])
    list_text = []
    for i in plainText_list:
        x = int(i,16)
        list_text.append(chr(x))

    return ''.join(list_text)

def decrypt(cipherText, roundKey):
    state_matrix = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]
    #print(cipherText)
    for i in range(4):
        for j in range(4):
            state_matrix[j][i] = cipherText[2*j+8*i:2*j+8*i+2]
    
    temp_key = [['', '', '', ''], ['', '', '', ''], ['', '', '', ''], ['', '', '', '']]

    i = 9
    # print("round key here:", roundKey)
    temp_key = [
        [roundKey[i+1][0], roundKey[i+1][4], roundKey[i+1][8], roundKey[i+1][12]],
        [roundKey[i+1][1], roundKey[i+1][5], roundKey[i+1][9], roundKey[i+1][13]],
        [roundKey[i+1][2], roundKey[i+1][6], roundKey[i+1][10], roundKey[i+1][14]],
        [roundKey[i+1][3], roundKey[i+1][7], roundKey[i+1][11], roundKey[i+1][15]],
    ]
    state_matrix = XOR_matrix(state_matrix, temp_key)
    for i in range(8, -2, -1):
        state_matrix = inverse_shift_rows(state_matrix)
        state_matrix = inverse_sub_bytes(state_matrix)
        # print("Round ",10 - i-1,": ",state_matrix)
        state_matrix = add_round_key2(state_matrix, roundKey, i)
        if(i != -1):
            state_matrix = inverse_mix_columns(state_matrix)
    return state_matrix_to_text(state_matrix)



def main():
    print("Enter the message to be encrypted: ")
    msg = input()
    # msg = "Two One Nine Two"
    print("Enter the key: ")
    key = input()
    # key = "ABCDabcd12344321"
    expanded_key = key_expansion(key)
    encrypted_message = encrypt(msg, expanded_key)
    print(encrypted_message)
    decrypted_text = decrypt(encrypted_message, expanded_key)
    print(decrypted_text)

if __name__ == '__main__':
   main()




