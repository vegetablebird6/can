import can
from genID import generateID
import encryption
import transform
import computerMAC
import vertifyHC
import asyncio

RECU_ID = 0
K = 18
SECU_ID = 1
groupAuthKey = b'f494409468476910ce95efd1f71c8759'
groupEnKey = b'f494409468476910ce95efd1f71c8759'
oseed = 22022
idseed = '110111111011111'



def print_message(msg):
    """Regular callback function. Can also be a coroutine."""
    print(msg)


async def receive(bus, ctr):
    """The loop for receiving."""
    reader = can.AsyncBufferedReader()
    logger = can.Logger("logfile.asc")
    listeners = [
        print_message,  # Callback function
        reader,  # AsyncBufferedReader() listener
        logger,  # Regular Listener object
    ]
    # Create Notifier with an explicit loop to use for scheduling of callbacks
    loop = asyncio.get_event_loop()
    notifier = can.Notifier(bus, listeners, loop=loop)
    # some known value
    RHV = 116701
    last_bit = 1
    # generate the leftid list
    leftidlist = generateID(idseed, groupAuthKey)
    # next hash chain's last value
    nextCLV = last_bit
    print("Start receiving messages")
    with open("plaintext.txt", "w") as file:
        while True:
            try:
                if ctr == 256:
                    ctr = 0
                # choose the leftid
                leftid = leftidlist[RECU_ID] << 18
                # set the receiver's filter
                can_filters = [{"can_id": leftid, "can_mask": 0x1ffc0000, "extended": True}]
                bus.set_filters(can_filters)
                # receive the message
                msg = await reader.get_message()
                rightid = msg.arbitration_id - leftid
                # if
                if ctr % K == K - 1:
                    nextCLVMAC = computerMAC.computerMAC(''.join([bin((nextCLV)).replace('0b','')]), groupAuthKey)
                    if nextCLVMAC != rightid:
                        continue
                    RHV = nextCLV
                    nextCLV = 0
                else:
                    if (vertifyHC.vertify(rightid, RHV) == False):
                        continue
                    RHV = rightid
                Enctext = encryption.aesEncrypt(groupEnKey, str(ctr))
                data_temp = int.from_bytes(msg.data, byteorder='big', signed=False)
                Enctext = Enctext >> ((16 - msg.dlc) * 8)
                Enctext = Enctext ^ data_temp
                last_bit = Enctext % 2
                # print(last_bit)
                plaintext = Enctext - last_bit
                msg.data = transform.int_to_datalist(plaintext, msg.dlc)
                msg.data[msg.dlc - 1] = (msg.data[msg.dlc - 1] >> 1)
                # print(msg.data)
                for j in range(msg.dlc):
                    file.write(str(msg.data[j]) + ' ')
                file.write('\n')
                ctr += 1
                nextCLV = (nextCLV << 1) + last_bit
            except KeyboardInterrupt:
                pass
    notifier.stop()


if __name__ == "__main__":
    with can.Bus(interface="socketcan", channel='vcan0', bitrate=500000) as bus:
        asyncio.run(receive(bus, 0))