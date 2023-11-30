# Liveness Analysis
#
#@author Kevin, Max, Valerie
#@category csce451.c3
#
#
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import SequenceNumber
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor


def getLive(it, livesets, dead):
    # global hfunc
    if it.hasNext():
        next = it.next()
        # print(next) #, "SEQ:", next.getSeqnum())
        # if next.getOpcode() == PcodeOp.INDIRECT:
        #     seq = SequenceNumber(next.getOutput().getAddress(), 0x53)
        #     print(seq)
        #     print(hfunc.getPcodeOp(seq))
        live = getLive(it, livesets, dead)
    else:
        return livesets["out"]
    # print(next)
    # print(live)
   
    if next.getOpcode() == PcodeOp.INDIRECT:
        return live
    elif next.getOpcode() == PcodeOp.COPY:
        if next.getOutput() not in live:
            dead.add(next)
        else:
            if next in dead:
                # print("Not Dead", next)
                dead.discard(next)
            live.discard(next.getOutput())
            if not next.getInput(0).isConstant():
                live.add(next.getInput(0))
    elif next.getOpcode() == PcodeOp.LOAD: # def
        if next.getOutput() not in live:
            dead.add(next)
            # print("Dead: ", next) 
        else:
            if next in dead:
                # print("Not Dead", next)
                dead.discard(next)
            live.discard(next.getOutput())
    elif next.getOpcode() == PcodeOp.STORE: # use input 2
        if not next.getInput(2).isConstant():
            live.add(next.getInput(2))
    elif next.getOpcode() == PcodeOp.CBRANCH: # use input 1
        if not next.getInput(1).isConstant():
            live.add(next.getInput(1))
    elif next.getOpcode() == PcodeOp.RETURN: # use input 0
        if next.getNumInputs() == 2:
            live.add(next.getInput(1))
    elif next.getOpcode() == PcodeOp.CALL:
        for i in range(1, next.getNumInputs()):
            if not next.getInput(i).isConstant():
                live.add(next.getInput(i)) 
    elif next.getOpcode() == PcodeOp.BRANCH:
        pass
    else:
        if next.getOutput() not in live:
            dead.add(next)
            # print("Dead: ", next) 
        else:
            if next in dead:
                # print("Not Dead", next)
                dead.discard(next)
            live.discard(next.getOutput())
            for input in next.getInputs():
                if not input.isConstant():
                    live.add(input)

    return live

def liveness():
    # global hfunc
    print("Potentially Dead PCode")
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    funcMan = currentProgram.getFunctionManager()
    for func in funcMan.getFunctions(True):

        hfunc = decomp.decompileFunction(func, 100, TaskMonitor.DUMMY).getHighFunction()
        pCodeBBs = hfunc.getBasicBlocks()

        livesets = {}
        dead = set()
        for bb in pCodeBBs:
            livesets[bb] = {"in": set(), "out": set()}


        for iteration in range(0,5):
            i = 0
            for bb in pCodeBBs:
                # print("\n\n\nPcode instruction in block " + str(i))
                it = bb.getIterator()
                live_in = getLive(it, livesets[bb], dead)
                livesets[bb]["in"] = live_in
                for inBB in range(bb.getInSize()):
                    livesets[bb.getIn(inBB)]["out"] = livesets[bb.getIn(inBB)]["out"].union(live_in)
                # print(live)

                i += 1
                # print(bb, live_in)
        if len(dead) == 0:
            continue
        print(func.getName())
        dead_addr = set()
        for op in dead:
            if op.getOutput() == None:
                continue
            address = op.getOutput().getPCAddress()
            if address in dead_addr:
                continue
            dead_addr.add(address)
            instruction = currentProgram.getListing().getInstructionAt(address)
            print(address.toString() + ": " + instruction.toString())
        print()


liveness()