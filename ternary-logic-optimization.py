#! /usr/bin/python3

import sys
from dataclasses import dataclass
from typing import Callable
import itertools

import z3

@dataclass
class Op:
    name: str
    eval: Callable[[z3.ExprRef, z3.ExprRef], z3.ExprRef]
    show: Callable[[str, str], str]

ops = [
    Op("set0",   lambda a, b: z3.BitVecVal(0b00000000, 8), lambda a, b: '0'),
    Op("set1",   lambda a, b: z3.BitVecVal(0b11111111, 8), lambda a, b: '-1'),
    Op("not",    lambda a, b: ~a,                          lambda a, b: f'~{a}'),
    Op("and",    lambda a, b: a & b,                       lambda a, b: f'{a} & {b}'),
    Op("or",     lambda a, b: a | b,                       lambda a, b: f'{a} | {b}'),
    Op("xor",    lambda a, b: a ^ b,                       lambda a, b: f'{a} ^ {b}'),
    # ARM has these, as do many other architectures (Alpha, PowerPC, RISC-V (Zbb)).
    # x86 has only andnot, and that only with the BMI1 extension.
    Op("andnot", lambda a, b: a & ~b,                      lambda a, b: f'{a} & ~{b}'),
    Op("ornot",  lambda a, b: a | ~b,                      lambda a, b: f'{a} | ~{b}'),
    Op("xornot", lambda a, b: a ^ ~b,                      lambda a, b: f'{a} ^ ~{b}'),
]

class SymbolicInsn:
    def __init__(self, prefix):
        self.opcode = z3.Int(f'{prefix}_op')
        self.r1 = z3.Int(f'{prefix}_r1')
        self.r2 = z3.Int(f'{prefix}_r2')

def eval(insns: [z3.ExprRef]) -> (z3.ExprRef, z3.ExprRef):
    A = z3.BitVecVal(0b11110000, 8)
    B = z3.BitVecVal(0b11001100, 8)
    C = z3.BitVecVal(0b10101010, 8)
    regs = [A, B, C]
    cycles = [z3.IntVal(0), z3.IntVal(0), z3.IntVal(0)] + [z3.Int(f'cycle_{i}') for i in range(len(insns))]
    constraints = []

    for i in range(len(insns)):
        in1 = regs[0]
        for j in range(1, len(regs)):
            in1 = z3.If(insns[i].r1 == j, regs[j], in1)
        in2 = regs[0]
        for j in range(1, len(regs)):
            in2 = z3.If(insns[i].r2 == j, regs[j], in2)

        cin1 = z3.IntVal(0)
        for j in range(3, len(regs)):
            cin1 = z3.If(insns[i].r1 == j, cycles[j], cin1)
        cin2 = z3.IntVal(0)
        for j in range(3, len(regs)):
            cin2 = z3.If(insns[i].r2 == j, cycles[j], cin2)

        result = ops[0].eval(in1, in2)
        for opcode in range(1, len(ops)):
            result = z3.If(insns[i].opcode == opcode, ops[opcode].eval(in1, in2), result)

        regs.append(result)

        constraints.append(cycles[3 + i] > cin1)
        constraints.append(cycles[3 + i] > cin2)
        # keep instructions sorted by cycle
        constraints.append(cycles[3 + i] >= cycles[3 + i - 1])
        # limit number of instructions issued in parallel
        # doesn't seem to be necessary
        #constraints.append(cycles[3 + i] >  cycles[3 + i - 2])

    return regs[-1], cycles, constraints

def solve(code, num_insns, max_cycles=None):
    insns = [SymbolicInsn(f'i{i}') for i in range(num_insns)]

    solver = z3.Solver()
    result, cycles, constraints = eval(insns)
    solver.add(constraints)
    solver.add(result == code)
    if max_cycles is not None:
        solver.add(cycles[-1] <= max_cycles)

    if solver.check() != z3.sat:
        return None

    model = solver.model()
    total_cycles =  model.eval(cycles[-1]).as_long()
    result = f'// code 0x{code:02x}, {num_insns} insns, {total_cycles} cycles\n'
    for i, insn in enumerate(insns):
        opcode = model.eval(insn.opcode).as_long()
        if opcode < 0 or opcode >= len(ops):
            opcode = 0
        r1 = model.eval(insn.r1).as_long()
        if r1 < 0 or r1 >= 3 + i:
            r1 = 0
        r2 = model.eval(insn.r2).as_long()
        if r2 < 0 or r2 >= 3 + i:
            r2 = 0
        if r1 < 3:
            r1 = 'ABC'[r1]
        else:
            r1 = f't{r1 - 3}'
        if r2 < 3:
            r2 = 'ABC'[r2]
        else:
            r2 = f't{r2 - 3}'
        c = model.eval(cycles[3 + i]).as_long()
        result += f't{i} = {ops[opcode].show(r1, r2)};\t// {c}\n'
    return result, total_cycles

def solve_code(code):
    for num_insns in itertools.count(1):
        for max_cycles in range(1, num_insns + 1):
            result = solve(code=code, num_insns=num_insns, max_cycles=max_cycles)
            if result:
                text, total_cycles = result
                print(text)
                print()
                # Try to find an alternative solution that has one more instruction but one less cycle.
                # E.g. for not/and/or/xor, changes 0x89, 0xa1, and 0xc1 from 4 insns, 4 cycles to 5 insns, 3 cycles.
                result = solve(code=code, num_insns=num_insns + 1, max_cycles=max_cycles - 1)
                if result:
                    print('// alternative solution')
                    text, total_cycles = result
                    print(text)
                    print()
                return

def main():
    for code in range(256):
        solve_code(code)

main()

