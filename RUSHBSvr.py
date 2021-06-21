from socket import *
import struct
import math 
from threading import Timer
import time

RECV_SIZE = 1500
PACKET_SIZE = 1472
PAYLOAD_SIZE = 1464

ENC_KEY = 11
DEC_KEY = 15
MOD = 249

GET = int('0010000000000010',2)
GET_CHK = int('0010010000000010',2)
GET_ENC = int('0010001000000010',2)
GET_CHK_ENC = int('0010011000000010',2)

FIN = int('0000100000000010',2)
FIN_CHK = int('0000110000000010',2)
FIN_ENC = int('0000101000000010',2)
FIN_CHK_ENC = int('0000111000000010',2)

DAT = int('0001000000000010',2)
DAT_CHK = int('0001010000000010',2)
DAT_ENC = int('0001001000000010',2)
DAT_CHK_ENC = int('0001011000000010',2)

NAK = int('0100000000000010',2)
NAK_DAT = int('0101000000000010',2)
NAK_DAT_CHK = int('0101010000000010',2)
NAK_DAT_ENC = int('0101001000000010',2)
NAK_DAT_CHK_ENC = int('0101011000000010',2)
NAK_FIN = int('0100100000000010',2)
NAK_FIN_CHK = int('0100110000000010',2)
NAK_FIN_ENC = int('0100101000000010',2)
NAK_FIN_CHK_ENC = int('0100111000000010',2)
NAK_ACK_FIN = int('1100100000000010',2)
NAK_ACK_FIN_CHK = int('1100110000000010',2)
NAK_ACK_FIN_ENC = int('1100101000000010',2)
NAK_ACK_FIN_CHK_ENC = int('1100111000000010',2)

ACK_DAT = int('1001000000000010',2)
ACK_DAT_CHK = int('1001010000000010',2)
ACK_DAT_ENC = int('1001001000000010',2)
ACK_DAT_CHK_ENC = int('1001011000000010',2)

ACK_FIN = int('1000100000000010',2)
ACK_FIN_CHK = int('1000110000000010',2)
ACK_FIN_ENC = int('1000101000000010',2)
ACK_FIN_CHK_ENC = int('1000111000000010',2)

FINs = [FIN, FIN_CHK, FIN_ENC, FIN_CHK_ENC]
GETs = [GET, GET_CHK, GET_ENC, GET_CHK_ENC]
ACK_DATs = [ACK_DAT, ACK_DAT_CHK, ACK_DAT_ENC, ACK_DAT_CHK_ENC]
ACK_FINs = [ACK_FIN, ACK_FIN_CHK, ACK_FIN_ENC, ACK_FIN_CHK_ENC]
NAK_DATs = [NAK_DAT, NAK_DAT_CHK, NAK_DAT_ENC, NAK_DAT_CHK_ENC]
DATs = [DAT, DAT_CHK, DAT_ENC, DAT_CHK_ENC]
CHKs = [FIN_CHK, FIN_CHK_ENC, ACK_FIN_CHK, ACK_FIN_CHK_ENC]

RECV_CHKs = [ACK_DAT_CHK, ACK_FIN_CHK, NAK_DAT_CHK, NAK_FIN_CHK]
RECV_ENCs = [ACK_DAT_ENC, ACK_FIN_ENC, NAK_DAT_ENC, NAK_FIN_ENC]
RECV_CHK_ENCs = [ACK_DAT_CHK_ENC, ACK_FIN_CHK_ENC, NAK_DAT_CHK_ENC, NAK_FIN_CHK_ENC]
# NAKs = [NAK, NAK_DAT, NAK_DAT_CHK, NAK_DAT_ENC, NAK_DAT_CHK_ENC,
#         NAK_FIN, NAK_FIN_CHK, NAK_FIN_ENC, NAK_FIN_CHK_ENC,
#         NAK_ACK_FIN, NAK_ACK_FIN_CHK, NAK_ACK_FIN_ENC, NAK_ACK_FIN_CHK_ENC]
 
def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):        
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff

# str --> byte 
def encryption(payload, key=ENC_KEY, n=MOD):
    result = b""
    for c in payload:
        if c == 0:
            break
        result += ((ord(c) ** key) % n).to_bytes(1, 'big')
    return result

# byte --> str 
def decryption(payload, key=DEC_KEY, n=MOD):
    result = ""
    for c in payload:
        if c == 0:
            break
        result += chr((c ** key) % n)
    return result

# def decryption(payload, key=DEC_KEY, n=MOD):
#     result = b""
#     for c in payload:
#         result += ((c ** key) % n).to_bytes(1, 'big')
#     return result

class Connection:
    def __init__(self):
        self._socket = None
        self._seq_num = {}    #1
        self._ack_num = {}      #0
        self._chk = {}          #0
        self._flag = {}          #0
        
        self._cli_seq_num = {}       #0
        self._last_cli_seq = {}       #0
        self._cli_ack_num = {}       #0
        self._cli_chk = {}           #0
        self._cli_flag = {}           #0
        self._cli_last_pkt = {}       #0
        
        self._content_list = {}       #[]
        self._data_index = {}            #0
        # self._nak = 0
        self._last_pkt = {}               #0
        self._timer = {}                   #0
        self._GET = {}                     #False
        self._NAK = {}
        # self._invalid_seq = False
        # invalid checksum enc flag
        self._pkt_chk = {}             #False
        self._pkt_enc = {}            #False
        self._timers = {}
        self._invalid_pkt_count = {}    #attack
        self._block_cli = []
        self._time = time.time()
        
    def connect(self):
        try:
            self._socket = socket(AF_INET, SOCK_DGRAM)
            self._socket.bind(('', 0))
            print(self._socket.getsockname()[1], flush=True)
            return True
        except socket.error as err:
            print("Error encountered when opening socket:\n", err)
            return False
        
    def recv_pkt(self):
        raw_data, info = self._socket.recvfrom(RECV_SIZE) #1 port 0 localhost
        if info[1] in self._block_cli:
            return
        # initial value 
        if self._seq_num.__contains__(info[1]) == False:
            self._seq_num[info[1]] = 1
            self._ack_num[info[1]] = 0      #0
            self._chk[info[1]] = 0          #0
            self._flag[info[1]] = 0 
            self._last_cli_seq[info[1]] = 0
            self._data_index[info[1]] = 0
            self._GET[info[1]] = False
            self._NAK[info[1]] = False
            self._pkt_chk[info[1]] = False
            self._pkt_enc[info[1]] = False
            self._timers[info[1]] = time.time()
            self._invalid_pkt_count[info[1]] = 1
        if round(self._timers[info[1]]-time.time()) == 2 and self._invalid_pkt_count[info[1]] >= 10:
            self._block_cli.append(info[1])
            return
        self.header_decode(raw_data, info[1])
        # invalid ack and seq 
        if self._last_cli_seq[info[1]] + 1 != self._cli_seq_num[info[1]]:
            self._invalid_pkt_count[info[1]] += 1
            return
        elif self._GET[info[1]] and self._cli_flag[info[1]] in GETs:
            self._invalid_pkt_count[info[1]] += 1
            return
        elif self._pkt_chk[info[1]] == True and self._pkt_enc[info[1]] == True:
            if self._cli_flag[info[1]] not in RECV_CHK_ENCs:
                self._invalid_pkt_count[info[1]] += 1
                return
        elif self._pkt_chk[info[1]] == True:
            if self._cli_flag[info[1]] not in RECV_CHKs:
                self._invalid_pkt_count[info[1]] += 1
                return
        elif self._pkt_enc[info[1]] == True:
            if self._cli_flag[info[1]] not in RECV_ENCs:
                self._invalid_pkt_count[info[1]] += 1
                return
        
        if self._cli_flag[info[1]] in GETs:
            if self._cli_flag[info[1]] == GET_ENC or self._cli_flag[info[1]] == GET_CHK_ENC:
                file_name = decryption(raw_data[8:].rstrip(b'\x00'))
            else:
                file_name = raw_data[8:].rstrip(b'\x00').decode('ascii')
            self._content_list[info[1]] = File_handler(file_name).file_spliter()
            # file does not exit 
            if type(self._content_list[info[1]]) == bool:
                if self._cli_flag[info[1]] == GET:
                    self._flag[info[1]] = FIN
                elif self._cli_flag[info[1]] == GET_CHK and compute_checksum(file_name.encode('ascii')) == self._cli_chk[info[1]]:
                    self._flag[info[1]] = FIN_CHK
                    self._pkt_chk[info[1]] = True
                elif self._cli_flag[info[1]] == GET_CHK and compute_checksum(file_name.encode()) != self._cli_chk[info[1]]:
                    self._invalid_pkt_count[info[1]] += 1
                    return
                elif self._cli_flag[info[1]] == GET_ENC:
                    self._flag[info[1]] = FIN_ENC
                    self._pkt_enc[info[1]] = True
                elif self._cli_flag[info[1]] == GET_CHK_ENC and compute_checksum(encryption(file_name)) == self._cli_chk[info[1]]:
                    self._flag[info[1]] = FIN_CHK_ENC
                    self._pkt_chk[info[1]] = True
                    self._pkt_enc[info[1]] = True
                elif self._cli_flag[info[1]] == GET_CHK_ENC and compute_checksum(encryption(file_name)) != self._cli_chk[info[1]]:
                    self._invalid_pkt_count[info[1]] += 1
                    return
                self.send_pkt(self._seq_num[info[1]], self._content_list[info[1]], info, self._flag[info[1]])
            else:
                if self._cli_flag[info[1]] == GET:
                    self._flag[info[1]] = DAT
                elif self._cli_flag[info[1]] == GET_CHK and compute_checksum(file_name.encode()) == self._cli_chk[info[1]]:
                    self._flag[info[1]] = DAT_CHK
                    self._pkt_chk[info[1]] = True
                elif self._cli_flag[info[1]] == GET_CHK and compute_checksum(file_name.encode()) != self._cli_chk[info[1]]:
                    self._invalid_pkt_count[info[1]] += 1
                    return
                elif self._cli_flag[info[1]] == GET_ENC:
                    self._flag[info[1]] = DAT_ENC
                    self._pkt_enc[info[1]] = True
                elif self._cli_flag[info[1]] == GET_CHK_ENC and compute_checksum(encryption(file_name)) == self._cli_chk[info[1]]:
                    self._flag[info[1]] = DAT_CHK_ENC
                    self._pkt_chk[info[1]] = True
                    self._pkt_enc[info[1]] = True
                elif self._cli_flag[info[1]] == GET_CHK_ENC and compute_checksum(encryption(file_name)) != self._cli_chk[info[1]]:
                    self._invalid_pkt_count[info[1]] += 1
                    return
                self.send_pkt(self._seq_num[info[1]], self._content_list[info[1]], info, self._flag[info[1]])
            self._GET[info[1]] = True
            self._cli_last_pkt[info[1]] = raw_data
        elif self._cli_flag[info[1]] in ACK_DATs:
            if self._seq_num[info[1]] - 1 != self._cli_ack_num[info[1]]: #invalid ack
                self._invalid_pkt_count[info[1]] += 1
                return
            
            if self._data_index[info[1]] == len(self._content_list[info[1]]):
                if self.flag_handler(ACK_DATs, FINs, raw_data[8:].rstrip(b'\x00'), info[1]):
                    self._invalid_pkt_count[info[1]] += 1
                    return
                self._timer[info[1]].cancel()
                self.send_pkt(self._seq_num[info[1]], self._content_list[info[1]], info, self._flag[info[1]])
            else:
                if self.flag_handler(ACK_DATs, DATs, raw_data[8:].rstrip(b'\x00'), info[1]):
                    self._invalid_pkt_count[info[1]] += 1
                    return
                self._timer[info[1]].cancel()
                self.send_pkt(self._seq_num[info[1]], self._content_list[info[1]], info, self._flag[info[1]])
                # self.send_pkt(self._seq_num, self._content_list, info, DAT)
            self._cli_last_pkt[info[1]] = raw_data
        elif self._cli_flag[info[1]] in NAK_DATs:
            if self.flag_handler(NAK_DATs, FINs, raw_data[8:].rstrip(b'\x00'), info[1]):
                self._invalid_pkt_count[info[1]] += 1
                return  
            self._timer[info[1]].cancel()
            self._NAK[info[1]] = True
            self.resend_pkt(info)
            # self.send_pkt(self._seq_num, self._content_list, info, DAT)        
        elif self._cli_flag[info[1]] in ACK_FINs:
            
            if self.flag_handler(ACK_FINs, ACK_FINs, raw_data[8:].rstrip(b'\x00'), info[1]):
                self._invalid_pkt_count[info[1]] += 1
                return  
            self._timer[info[1]].cancel()
            # header = self.header_encode(self._seq_num, 0, 0, ACK_FIN)
            # self._socket.sendto(header, info)
            # self._seq_num += 1
            self._ack_num[info[1]] = self._cli_seq_num[info[1]]
            self.send_pkt(self._seq_num[info[1]], self._content_list[info[1]], info, self._flag[info[1]], self._ack_num[info[1]])
            self._seq_num[info[1]] = 1
            self._data_index[info[1]] = 0
            self._GET[info[1]] = False
            self._cli_last_pkt[info[1]] = raw_data
            self._pkt_chk[info[1]] = False
            self._pkt_enc[info[1]] = False
            del[self._seq_num[info[1]]]
    
    # send flag handler 
    def flag_handler(self, recv_flag, send_flag, encoded_payload, port):
        if self._cli_flag[port] == recv_flag[0]:
            self._flag[port] = send_flag[0]
        elif self._cli_flag[port] == recv_flag[1] and compute_checksum(encoded_payload) == self._cli_chk[port]:
            self._flag[port] = send_flag[1]
        elif self._cli_flag[port] == recv_flag[1] and compute_checksum(encoded_payload) != self._cli_chk[port]:
            self._invalid_pkt_count[port] += 1
            return True
        elif self._cli_flag[port] == recv_flag[2]:
            self._flag[port] = send_flag[2]
        elif self._cli_flag[port] == recv_flag[3] and compute_checksum(encoded_payload) == self._cli_chk[port]:
            self._flag[port] = send_flag[3]
        elif self._cli_flag[port] == recv_flag[3] and compute_checksum(encoded_payload) != self._cli_chk[port]:
            self._invalid_pkt_count[port] += 1
            return True
        
    def send_pkt(self, seq_num, content_list, info, flag, ack=0):
        payload = b''
        if flag in DATs:
            if flag == DAT:
                payload = content_list[self._data_index[info[1]]].encode()  
                self._chk[info[1]] = 0
            elif flag == DAT_CHK:
                payload = content_list[self._data_index[info[1]]].encode() 
                self._chk[info[1]] = compute_checksum(payload) 
            elif flag == DAT_ENC:
                payload = encryption(content_list[self._data_index[info[1]]]) 
                self._chk[info[1]] = 0
            elif flag == DAT_CHK_ENC:
                payload = encryption(content_list[self._data_index[info[1]]]) 
                self._chk[info[1]] = compute_checksum(payload)
            self._data_index[info[1]] += 1
        else: 
            if flag in CHKs:
                self._chk[info[1]] = compute_checksum("")
            else:
                self._chk[info[1]] = 0
        for i in range(len(payload), PAYLOAD_SIZE):
            payload += b'\0'
        header = self.header_encode(seq_num, ack, self._chk[info[1]], flag)
        self._socket.sendto(header+payload, info)
        if flag not in ACK_FINs:
            self._timer[info[1]] = Timer(4, self.resend_pkt, (info,))
            self._timer[info[1]].start()
        self._last_pkt[info[1]] = header+payload
        self._last_cli_seq[info[1]] = self._cli_seq_num[info[1]]
        self._seq_num[info[1]] += 1
            
    def resend_pkt(self, info):
        if self._NAK[info[1]]:
            self._last_cli_seq[info[1]] = self._cli_seq_num[info[1]]
            self._NAK[info[1]] = False
        else:
            self.header_decode(self._cli_last_pkt[info[1]], info[1])       
        self._socket.sendto(self._last_pkt[info[1]], info) 
        self._timer[info[1]] = Timer(4, self.resend_pkt, (info,))
        self._timer[info[1]].start()
        
    def header_decode(self, raw_data, port):
        self._cli_seq_num[port] = int.from_bytes(raw_data[:2], byteorder='big')
        self._cli_ack_num[port] = int.from_bytes(raw_data[2:4], byteorder='big')
        self._cli_chk[port] = int.from_bytes(raw_data[4:6], byteorder='big')
        self._cli_flag[port] = int.from_bytes(raw_data[6:8], byteorder='big')
    
    def header_encode(self, seq, ack, chk, flag):
        seq_b = seq.to_bytes(2, byteorder='big')
        ack_b = ack.to_bytes(2, byteorder='big')
        chk_b = chk.to_bytes(2, byteorder='big')
        flag_b = flag.to_bytes(2, byteorder='big')
        return seq_b + ack_b + chk_b + flag_b
        
    def run(self):
        # count = 0
        while True:
            self.recv_pkt()
            if round(time.time()-self._time) == 5: #and sum(self._invalid_pkt_count.values()) > 30:
                # for i in self._invalid_pkt_count.keys():
                #     self._block_cli.append(i)
                if sum(self._invalid_pkt_count.values()) > 30:
                    for i in self._invalid_pkt_count.keys():
                        self._block_cli.append(i)
                    time.sleep(10)
                self._invalid_pkt_count.clear()
                self._time = time.time()
            
class File_handler:
    def __init__(self, file_name):
         self._file_name = file_name
        
    def file_spliter(self):
        content_list = []
        try:
            file = open(self._file_name)
            content = file.read()
            size = math.ceil(len(content)/PAYLOAD_SIZE)
            for i in range(size):
                content_list.append(content[i*PAYLOAD_SIZE:(i+1)*PAYLOAD_SIZE])
            file.close()
            return content_list
        except (IOError, UnicodeEncodeError) as e:
            return False    

def main():
    conn = Connection()
    conn.connect()
    conn.run()
    
if __name__ == "__main__":
    main()
    