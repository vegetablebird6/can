import random


def generatedata():
    list = []
    for i in range(8):
        list.append(random.getrandbits(7))
    return list


def generatedataset():
    for i in range(1000):
        yield generatedata()


if __name__ == "__main__":
    with open("Dataset.txt", "w") as file:
        for i in generatedataset():
            for j in i:
                file.write(str(j) + ' ')
            file.write('\n')
