
from collections.abc import Callable, Iterable, Iterator, MutableSequence
import operator
from typing import Any, Generic, Literal, Tuple, TypeVar

T = TypeVar('T')

class BTreeNode(Generic[T]):
    leaf: bool
    keys: MutableSequence[T]
    children: MutableSequence["BTreeNode[T]"]

    def __init__(self, leaf: bool):
        self.leaf = leaf
        self.keys = []
        self.children = []

class BTree(Generic[T]):
    root: BTreeNode[T]
    order: int
    lt: Callable[[T, T], bool]
    eq: Callable[[T, T], bool]

    def __init__(self, order: int, lt: Callable[[T, T], bool] = operator.lt, eq: Callable[[T, T], bool] = operator.eq) -> None:
        self.root = BTreeNode(True)
        self.order = order
        self.lt = lt
        self.eq = eq

    def insert(self, k: T) -> None:
        if len(self.root.keys) == (2 * self.order) - 1:
            tmp = BTreeNode(False)
            tmp.children.append(self.root)
            self.split_child(tmp, 0)
            self.root = tmp
        self.insert_non_full(self.root, k)

    def insert_non_full(self, x: BTreeNode[T], k: T):
        while True:
            for i, kp in enumerate(reversed(x.keys)):
                if self.lt(kp, k):
                    break
            else:
                i = len(x.keys)
            i = len(x.keys) - i
            if x.leaf:
                x.keys.insert(i, k)
                break
            else:
                if len(x.children[i].keys) == (2 * self.order) - 1:
                    self.split_child(x, i)
                    if self.lt(x.keys[i], k):
                        i += 1
                x = x.children[i]

    def split_child(self, x, i):
        order = self.order
        y = x.children[i]
        z = BTreeNode(y.leaf)
        x.children.insert(i + 1, z)
        x.keys.insert(i, y.keys[order - 1])
        z.keys = y.keys[order:]
        y.keys = y.keys[:order - 1]
        if not y.leaf:
            z.children = y.children[order:]
            y.children = y.children[:order]

    def search(self, k: T, node: BTreeNode[T] | None = None) -> Tuple[BTreeNode[T], int] | None:
        if node is None:
            node = self.root
        while True:
            for i, kp in enumerate(node.keys):
                if not self.lt(kp, k):
                    if self.eq(k, node.keys[i]):
                        return (node, i)
                    break
            else:
                i = len(node.keys)
            if node.leaf:
                return None
            else:
                node = node.children[i]

    def __iter__(self) -> "BTreeIter[T]":
        return BTreeIter(self)

    def delete(self, k: T, x: BTreeNode[T] | None = None) -> T | None:
        if x is None:
            x = self.root
        while True:
            # TODO
            return None

    def print(self, sfun: Callable[[T], str] = str, x: BTreeNode[T] | None = None, pfx: str = "") -> None:
        if x is None:
            x = self.root
        if x.leaf:
            for k in x.keys:
                print(pfx + sfun(k))
        else:
            for i, k in enumerate(x.keys):
                self.print(sfun, x.children[i], pfx + "  ")
                print(pfx + sfun(k))
            else:
                self.print(sfun, x.children[-1], pfx + "  ")

U = TypeVar('U')

def pair_rel_first(rel: Callable[[T, T], bool]) -> Callable[[Tuple[T, Any], Tuple[T, Any]], bool]:
    def new_rel(k1: Tuple[T, Any], k2: Tuple[T, Any]) -> bool:
        return rel(k1[0], k2[0])
    return new_rel

def pair_first(t: Tuple[T, U]) -> T:
    return t[0]

def pair_second(t: Tuple[T, U]) -> U:
    return t[1]

class BTreeMap(Generic[T, U]):
    tree: BTree[Tuple[T, U]]
    length: int

    def __init__(self, order: int, lt: Callable[[T, T], bool] = operator.lt, eq: Callable[[T, T], bool] = operator.eq):
        self.tree = BTree(order, pair_rel_first(lt), pair_rel_first(eq))
        self.length = 0

    def __getitem__(self, key: T) -> U:
        ret = self.tree.search((key, None)) # type: ignore
        if ret is None:
            raise KeyError(key)
        return ret[0].keys[ret[1]][1]

    def __setitem__(self, key: T, value: U):
        loc = self.tree.search((key, None)) # type: ignore
        if loc is None:
            self.tree.insert((key, value))
            self.length += 1
        else:
            loc[0].keys[loc[1]] = (key, value)

    def __iter__(self) -> Iterator[T]:
        return map(pair_first, iter(self.tree))

    def __len__(self) -> int:
        return self.length

    def get(self, key: T, default: U) -> U:
        ret = self.tree.search((key, default))
        if ret is None:
            return default
        else:
            return ret[0].keys[ret[1]][1]

    def __contains__(self, key: T) -> bool:
        return self.tree.search((key, None)) is not None # type: ignore

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BTreeMap):
            return self.length == other.length and all(x == y for x, y in zip(self.items(), other.items()))
        else:
            return NotImplemented

    def items(self) -> Iterator[Tuple[T, U]]:
        return iter(self.tree)

    def values(self) -> Iterator[U]:
        return map(pair_second, iter(self.tree))

class BTreeIter(Generic[T]):
    # yes, I brewed up this algorithm myself. it's essentially just a rolled-out
    # version of the search algorithm.
    stack: MutableSequence[Tuple[BTreeNode[T], int]]

    def __init__(self, tree: BTree[T]) -> None:
        self.stack = [(tree.root, 0)]
        node = tree.root
        while not node.leaf:
            node = node.children[0]
            self.stack.append((node, 0))

    def __iter__(self) -> "BTreeIter[T]":
        return self

    def __next__(self) -> T:
        while len(self.stack) > 0:
            node, i = self.stack[-1]
            if i < len(node.keys):
                ret = node.keys[i]
                self.stack[-1] = (node, i + 1)
                if node.leaf:
                    return ret
                node = node.children[i + 1]
                self.stack.append((node, 0))
                while not node.leaf:
                    node = node.children[0]
                    self.stack.append((node, 0))
                return ret
            self.stack.pop()
        raise StopIteration
