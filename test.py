import time
# # s1 = 'hh'
# # s = s1+b'\0' 
# # print(int.from_bytes(s, byteorder='big'))
# import time

# GET = int('0010000000000010', 2)
# print(GET)

# # if True and 1:
# #     print("hh")
# s = "aabbccd"
# l = []
# for i in range(4):
#     l.append(s[i*2:(i+1)*2])
# print(l)

# # f = open('files/fil.txt').read()
# # print(f, type(f), type(1))
# def ttt():
#     file = 'files/fil.txt'
#     try:
#         f = open(file)
#         return 1,2
#     except IOError:
#         return False



# print(ttt())
# # b'\x00\x01\x00\x00\x00\x00 \x02'
# # b'\x00\x01\x00\x00\x00\x00 \x02'
# i = 1
# i1 = 0
# i2 = 8194
# c = i.to_bytes(2, byteorder='big')
# c1 = i1.to_bytes(2, byteorder='big')
# c2 = i2.to_bytes(2, byteorder='big')
# print(c+c1+c1+c2)

# a12=[1,2]
# a12= False
# print(type(a12))

# b2 = b''
# b3 = b'/0'

# print(b2, b3, b2+b3, b3==(b2+b3))
# print("\033[1;36m" + "fdffds" + "\033[0m")

# if type(a12) == bool:
#     print("hh")
    
# t = time.time()
# print(t) 
# time.sleep(1)   
# print(round(time.time()-t))


# s10 = b"avvv"
# for i in s10:
#     print(i)
    
# a10="a"
# print(a10.encode())
# a11=97
# print(a11.to_bytes(1, 'big'))
# print(a11)


# print(1!=2)


# def aaa(a):
#     if a==1:
#         print("wozhenhao")
#     else:
#         return True

# if aaa(1):
#     print("kkkkkkkkkkk")
    
    
# def carry_around_add(a, b):
#     c = a + b
#     return (c & 0xffff) + (c >> 16)

# def compute_checksum(message):
#     b_str = message
#     if len(b_str) % 2 == 1:
#         b_str += b'\0'
#     checksum = 0
#     for i in range(0, len(b_str), 2):        
#         w = b_str[i] + (b_str[i+1] << 8)
#         checksum = carry_around_add(checksum, w)
#     return ~checksum & 0xffff

# print(compute_checksum(""))



# def encryption(payload, key=11, n=249):
#     result = b""
#     for c in payload:
#         if c == 0:
#             break
#         result += ((ord(c) ** key) % n).to_bytes(1, 'big')
#     return result

# def decryption(payload, key=15, n=249):
#     result = ""
#     for c in payload:
#         if c == 0:
#             break
#         result += chr((c ** key) % n)
#     return result

# x10 = b'i\xbax\x8c\x85\x80i\xbax\x8c\xe8V\xb7V'
# x11 = b'~\xa2\xb1\xef\x16G~\xa2\xb1\xef\x88\x92\x1e\x92'
# print("+++++++++++++")
# print(decryption(x11))

# print(encryption('files/file.txt'))
# print(ord('f'))
# print(((ord('f') ** 11) % 249))
# print((105 ** 15) % 249)
# print(chr(102))

# print('-------------------')
# for i in x10:
#     print(i)
    
    
    
    
# # print(x10.decode())
# # print(int.from_bytes(x10, byteorder='big'))
# print(decryption(x10))


# t = [1,2]

# if 3 not in t:
#     print(3)


# d1 = {1234:0, 123:1}
# d2 = {345:3}
# d1[1234] = 1
# d1[1235] = 2
# d1[123] = d2[345]
# d2[345] = 6
# print(d1)
# print(d2)

# del[d1[1234]]
# d1[1235] += 1
# print(d1.__contains__(1236) == False)
# print(d1)


t1 = time.time()
time.sleep(1)

print(round(time.time()-t1)==1)


a = []
a.append(1)
print(a)

d = {"a":1,"b":2}
d.clear()
print(d)

# for i in d.keys():
#     print(i)
# print(sum(d.values()))

# while True:
#     if round(time.time()-t1)==5:
#         print("hhhhhhhh")


# while True:
#     print("aibaiabbai")
#     time.sleep(5)

# print("*~ó*~óÝîã±ã".encode('ascii'))

def decryption(payload, key=15, n=249):
    result = b""
    for c in payload:
        result += ((c ** key) % n).to_bytes(1, 'big')
    return result


e = b'i\xbax\x8c\x85\x80i\xbax\x8c\xe8V\xb7V'

e1 = b'~\xa2\xb1\xef\x16G~\xa2\xb1\xef\x88\x92\x1e\x92'
de = decryption(e)
de1 = decryption(e1)
result =""
for i in de1:
    result+=chr(i)

print(decryption(e).decode())

print(decryption(e1).decode("ascii"))


print(result)

