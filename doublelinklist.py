class Node(object):
    """双向链表节点"""
    def __init__(self, item):
        self.item = item
        self.next = None
        self.prev = None


class DLinkList(object):
    """双向链表"""
    def __init__(self):
        self._head = None

    def is_empty(self):
        """判断链表是否为空"""
        return self._head == None

    def length(self):
        """返回链表的长度"""
        cur = self._head
        count = 0
        while cur != None:
            count += 1
            cur = cur.next
        return count

    def travel(self):
        """遍历链表"""
        cur = self._head
        while cur != None:
            print(cur.item)
            cur = cur.next
        print("over")

    def add(self, item):
        node = Node(item)
        if self.is_empty():
            # 如果是空链表，将_head指向node
            self._head = node
            return True
        cur = self._head
        while cur.next != None and cur.item < node.item:
             cur = cur.next
        if cur.item < node.item:
            cur.next = node
            node.prev = cur
            return True
        if cur.item > node.item:
            if cur.prev == None:
                node.next = cur
                cur.prev = node
                self._head = node
            else:
                node.prev = cur.prev
                node.next = cur
                cur.prev.next = node
                cur.prev = node
            return True
        return False

    def getitem(self, index):
        cur = self._head
        if index < 0 or index > self.length() - 1:
            return None
        count = 0
        while count < index:
            cur = cur.next
            count += 1
        return cur.item

    def search(self, item):
        """查找元素是否存在"""
        cur = self._head
        while cur != None:
            if cur.item == item:
                return True
            cur = cur.next
        return False
