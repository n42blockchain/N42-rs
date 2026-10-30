"""Executable CALLSTATUS semantics vectors, NOT an opcode implementation.

These two evaluators check frame-local registers and discarded speculation.
They do not execute EVM bytecode or implement state-gas accounting. A real N42
serial/parallel adapter must consume the vectors before compatibility is claimed.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class Frame:
    end: str = 'success'
    children: tuple = ()


def recursive(frame):
    last, seen = 0, False
    for child in frame.children:
        last = recursive(child)
        seen |= last >= 2
    if frame.end == 'halt': return 2
    if frame.end == 'not_started': return 1
    return (1 if frame.end == 'revert' else 0) | (4 if seen else 0)


def iterative(root):
    stack = [(root, 0, False)]
    result = 0
    while stack:
        frame, next_child, seen = stack.pop()
        if next_child:
            seen |= result >= 2
        if next_child < len(frame.children):
            stack.append((frame, next_child + 1, seen))
            stack.append((frame.children[next_child], 0, False))
        else:
            if frame.end == 'halt': result = 2
            elif frame.end == 'not_started': result = 1
            else: result = int(frame.end == 'revert') + 4 * int(seen)
    return result


def vectors():
    # Case numbering follows draft EIP-8456, retrieved 2026-10-30.
    # Concrete bytecode/gas setup is a pending adapter, not hidden in this model.
    success = Frame(); revert = Frame('revert'); halt = Frame('halt')
    expected = [0,0,0,0,0,0,0,1,1,1,0,2,2,2,2,2,2,2,1,1,1,1,2,2,1,0,0,0,2,1,2,2,2,2,2,2,1,1,0,
                None,None,None,0,1,5,5,1,5,5,4,5,2,5,5,5,4,0,None]
    cases = []
    for number, code in enumerate(expected, 1):
        frame = {0: success, 1: revert, 2: halt}.get(code)
        if code == 5: frame = Frame('revert', (halt,))
        if code == 4: frame = Frame('success', (halt,))
        if number in (19,20,21,22,37,38): frame = Frame('not_started')
        if number in (48,49): frame = Frame('revert', (halt, success))
        if number == 51: frame = Frame('revert', (Frame('success', (halt,)),))
        if number == 52: frame = Frame('halt', (halt,))
        if number in (53,54):
            frame = Frame('revert', (Frame('revert', (halt,)),))
            if number == 54: frame = Frame('revert', (frame,))
        cases.append((number, code, frame))
    return cases
