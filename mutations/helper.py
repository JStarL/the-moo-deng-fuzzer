from typing import Iterator, TypeVar, List

T = TypeVar('T')


def round_robin(iterators: List[Iterator[T]]) -> Iterator[T]:
    """Yields items from each iterator in round-robin fashion, until all iterators are exhausted."""
    idx = 0
    while iterators:
        it = iterators[idx]
        try:
            yield next(it)
        except StopIteration:
            iterators.pop(idx)
        else:
            idx = (idx + 1) % len(iterators) if iterators else 0


if __name__ == "__main__":
    iterators = [iter([1, 2, 3]), iter([4, 5]), iter([6, 7, 8, 9])]
    result = list(round_robin(iterators))
    print(result)
