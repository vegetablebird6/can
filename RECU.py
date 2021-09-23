import can
from genID import generateID
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
idseed = '110111111011111011'


def receive(bus, ctr):
    """The loop for receiving."""
    # some known value
    count = 0
    RHV = 116701
    last_bit = 1
    # generate the leftid list
    leftidlist = generateID(idseed, 0, 25, groupAuthKey)
    # next hash chain's last value
    nextCLV = last_bit
    print("Start receiving messages")
    while True:
        # choose the leftid
        leftid = leftidlist.getitem(RECU_ID) << 18
        # set the receiver's filter
        can_filters = [{"can_id": leftid, "can_mask": 0x1ffc0000, "extended": True}]
        bus.set_filters(can_filters)
        # receive the message
        rx_msg = bus.recv()
        if rx_msg is None:
            continue
        rightid = rx_msg.arbitration_id - leftid
        if count == K - 1:
            nextCLVMAC = computerMAC.computerMAC(bin(nextCLV)[2:], groupAuthKey)
            if nextCLVMAC != rightid:
                continue
            RHV = nextCLV
            nextCLV = 0
        else:
            if (vertifyHC.vertify(rightid, RHV) == False):
                continue
            RHV = rightid
        Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
        data_temp = int.from_bytes(rx_msg.data, byteorder='big', signed=False)
        Enctext = Enctext >> ((16 - rx_msg.dlc) * 8)
        Enctext = Enctext ^ data_temp
        last_bit = Enctext % 2
        # print(last_bit)
        plaintext = Enctext - last_bit
        rx_msg.data = transform.int_to_datalist(plaintext, rx_msg.dlc)
        rx_msg.data[rx_msg.dlc - 1] = (rx_msg.data[rx_msg.dlc - 1] >> 1)
        print(rx_msg.data)
        ctr = (ctr + 1) % 256
        count = (count + 1) % K
        nextCLV = (nextCLV << 1) + last_bit
    print("Stopped receiving messages")


if __name__ == "__main__":
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        receive(bus, CTR)
    print(CTR)
