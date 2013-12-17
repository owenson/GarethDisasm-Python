import os,md5,sys
from PyQt4.QtGui import *
from DisasmWin import *
sys.path.append("distorm-read-only/build/lib.linux-i686-2.7/")
#sys.path.append("distorm-read-only/build/lib")
#from pydasm import *

BASE_ADDR = 0x0;
import distorm3
import mmap
from utils import *

labels = {}
tovisit = []
disassembly = {}

def memoryOffsetToFileOffset(off):
	global BASE_ADDR;
	return off - BASE_ADDR;

def fileOffsetToMemoryOffset(off):
	global BASE_ADDR;
	return off + BASE_ADDR;

fd = file(os.sys.argv[1], 'r+b')
data = mmap.mmap(fd.fileno(), 0)

fileLen = len(data)

#    print off, inst.lower()
print "PASS 1"

# first pass
labels[BASE_ADDR] = {'type':'sub', 'name':'_start', 'xrefs':[], 'calls_out':[]}
tovisit.append(BASE_ADDR)

offset = 0
while True:
    if len(tovisit) == 0:
        break
    offset = tovisit.pop()

    terminalInstruction = False

    while((not disassembly.has_key(offset)) and (not terminalInstruction) and memoryOffsetToFileOffset(offset) < fileLen):
        if offset in tovisit:
            tovisit.remove(offset)

        inst = distorm3.Decode(offset, data[memoryOffsetToFileOffset(offset):], distorm3.Decode16Bits)[0]
        #print offset,inst
        ins = inst['mnemonic']
        ops = inst['ops']
        #inst = get_instruction(data[offset:], MODE_16)

        #if not inst:
        #    print "fail"
        #    break

        #ins = get_instruction_string(inst, FORMAT_INTEL, offset)

        if (ins.startswith("call") or ins[0] == 'j' or ins.startswith("loop")) and ops[0].isdigit():
            newoff = int(ops[2:],16)

            if (not newoff in tovisit) and (not disassembly.has_key(newoff)):
                tovisit.append(newoff)

            if labels.has_key(newoff):
                if not offset in labels[newoff]['xrefs']:
                    labels[newoff]['xrefs'].append(offset)
            else:
                labels[newoff] = {}
                labels[newoff]['calls_out'] = []
                labels[newoff]['xrefs'] = [ offset ]
                labels[newoff]['type'] = ('sub' if ins.startswith('call') else 'lbl')


        disassembly[offset] = inst

        if(ins.startswith("ret") or ins.startswith("jmp")):
            terminalInstruction = True;
        else:
            offset += inst['size'];

        if(disassembly.has_key(offset)): #next instruction already visited - so stop
            break

print "PASS 2"

# second pass - does function related passing
inProcLabel = False
offset = BASE_ADDR
while offset < fileOffsetToMemoryOffset(fileLen):
    if labels.has_key(offset):
        if labels[offset]['type'] == "sub":
           inProcLabel = offset

    if disassembly.has_key(offset):
        inst = disassembly[offset]
        ins = inst['mnemonic']

        if(ins.startswith("call") and inProcLabel):  # collate calls out of function
            labels[inProcLabel]['calls_out'].append(int(inst['ops'][2:],16))

        if(ins.startswith("ret") and inProcLabel):  #detect function termination
            if not labels[inProcLabel].has_key('end'):
                labels[inProcLabel]['end'] = offset + inst['size']
            inProcLabel = False

        offset += inst['size']
    else:
        offset += 1

#pass 3 - print
print "PASS 3: Display"
inProcLabel = False
def disassemblyText(disassembly, labels, start, end):
    str = '<pre style="font-family: monospace; font-size: 14px;">'
    offset = start
    while offset < end:
        if labels.has_key(offset):
            if labels[offset]['type'] == "sub":
               str += "\n\n---STARTPROC---\n"
               inProcLabel = offset
            str += "<span style='color:blue'>%s_%x</span>:\n" % (labels[offset]['type'], offset)

        if disassembly.has_key(offset):
            inst = disassembly[offset]

            ins = inst['instr']

            str += "<span style='color:red'>%08x</span>:\t%s\n" % (offset,ins)

            if(ins.startswith("ret") and inProcLabel):  #detect function termination
                str += "<span style='color:blue'>---ENDPROC---  ; sub_%x ; length = %d bytes ; %d calls out</span>\n\n" % (inProcLabel, labels[inProcLabel]['end'] - inProcLabel, len(labels[inProcLabel]['calls_out']))
                inProcLabel = False


            offset += inst['size']
        else:
            str += "<span style='color:red'>%08x</span>:\tdb 0x%02x %s\n" % (offset, ord(data[offset]), data[offset] if isPrintable(data[offset]) else '')
            offset += 1
    str += "</pre>"
    return str

dtext = disassemblyText(disassembly, labels, BASE_ADDR, BASE_ADDR+fileLen)

print "TOTaL LBLS", len(labels)

#for lbladdr in labels:
#    lbl = labels[lbladdr]
#    if lbl['type'] != 'sub':
#        continue
#    if lbl.has_key('end'):
#        instructions = data[memoryOffsetToFileOffset(lbladdr):memoryOffsetToFileOffset(lbl['end'])]
#        print "%x %d %d %d %s" % (lbladdr, lbl['end'] - lbladdr, len(lbl['calls_out']), len(lbl['xrefs']), md5.new(instructions).hexdigest())
def graphFuncs(labels):
    str = 'digraph {'
    for lbladdr in labels:
        lbl = labels[lbladdr]
        if lbl['type'] != 'sub':
            continue
        lblname = getLblName(labels, lbladdr)
        for xref in set(lbl['calls_out']):
            xrefnm = getLblName(labels, xref)
            str += "{} -> {}\n".format(lblname, xrefnm)
    str += "}"
    return str

print graphFuncs(labels)
app = QApplication(sys.argv)
ex = DisasmWin(dtext, labels)
sys.exit(app.exec_())

