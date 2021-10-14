import random


def generatedata():
    list = []
    num = random.randint(1, 7)
    for i in range(num):
        list.append(random.getrandbits(8))
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
