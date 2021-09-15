import can
from generateID import generateID
from generateHC import generateHC
from generateRS import generateRS, getbit
import encryption
import transform
import computerMAC
import vertifyHC

RECU_ID = 0
CTR = 0
K = 18
SECU_ID = 1
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
oseed = 22022
idseed = '110111111011111'

def receive(bus, ctr):
    """The loop for receiving."""
    # some known value
    RHV = 116701
    last_bit = 1
    count = 1
    # generate the leftid list
    leftidlist = generateID(idseed, groupAuthKey)
    # next hash chain's last value
    nextCLV = last_bit
    print("Start receiving messages")
    while True:
        # if count == K + 1:
        #     nextCLV = 0
        #     count = 1
        # choose the leftid
        leftid = leftidlist[RECU_ID] << 18
        # set the receiver's filter
        can_filters = [{"can_id": leftid, "can_mask": 0x1ffc0000, "extended": True}]
        bus.set_filters(can_filters)
        # receive the message
        rx_msg = bus.recv(1)
        if rx_msg is None:
            continue
        rightid = rx_msg.arbitration_id - leftid
        # if
        if ctr % K == K - 1:
            print(nextCLV)
            nextCLVMAC = computerMAC.computerMAC(''.join([bin((nextCLV)).replace('0b','')]), groupAuthKey)
            if nextCLVMAC != rightid:
                continue
            RHV = nextCLV
        else:
            if (vertifyHC.vertify(rightid, RHV) == False):
                continue
            RHV = rightid
        Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
        data_temp = int.from_bytes(rx_msg.data, byteorder='big', signed=False)
        Enctext = Enctext >> ((16 - rx_msg.dlc) * 8)
        Enctext = Enctext ^ data_temp
        last_bit = Enctext % 2
        nextCLV = (nextCLV << 1) + last_bit
        print(last_bit)
        count += 1
        plaintext = Enctext - last_bit
        rx_msg.data = transform.int_to_datalist(plaintext, rx_msg.dlc)
        rx_msg.data[rx_msg.dlc - 1] = (rx_msg.data[rx_msg.dlc - 1] >> 1)
        print(rx_msg.data)
        ctr += 1
    print("Stopped receiving messages")

if __name__ == "__main__":
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        receive(bus, CTR)