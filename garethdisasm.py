import os,md5,sys
from PyQt4.QtGui import *
from DisasmWin import *
import sqlite3
import json
import pefile

sys.path.append("distorm-read-only/build/lib/")
#sys.path.append("distorm-read-only/build/lib")
#from pydasm import *
BASE_ADDR = 0x0;
import distorm3
import mmap
from utils import *
import re

labels = {}
tovisit = []
disassembly = {}

# INITIALISE SQLITE DATABASE ----------------
dbcon = sqlite3.connect(sys.argv[1] + ".db")
dbcon.row_factory = sqlite3.Row
dbcur = dbcon.cursor()
LABEL_FUNC = 0
LABEL_LABEL = 1
LABEL_DATA = 2
LABEL_IMPORT = 3
dbcur.execute("DROP TABLE IF EXISTS disasm")
dbcur.execute("CREATE TABLE disasm (offset int, mnemonic text, ops text, size int, formatted text, comment text, meta text, primary key(offset))")
dbcur.execute("DROP TABLE IF EXISTS labels")
dbcur.execute("CREATE TABLE labels (offset int, labelName text, labelType int, meta text, primary key(offset))")
dbcur.execute("DROP TABLE IF EXISTS xrefs")
dbcur.execute("CREATE TABLE xrefs (fromOffset int, toOffset int, primary key(fromOffset))")
dbcur.execute("DROP TABLE IF EXISTS segments")
dbcur.execute("CREATE TABLE segments (id integer primary key, name text, fileOffset int, fileSize int, virtOffset int, virtSize int, read bool, write bool, execute bool)")

#dbcur.execute("DROP TABLE IF EXISTS imports")
#dbcur.execute("CREATE TABLE imports (id integer primary key, name text, addr int)")
# END INITIALISE SQLITE DATABASE ----------------

# OPEN AND PARSE PE FILE ----------------
pe = pefile.PE(sys.argv[1], fast_load=True)
imgBase = pe.OPTIONAL_HEADER.ImageBase
entryPt = pe.OPTIONAL_HEADER.AddressOfEntryPoint + imgBase

print ("Reading sections")
for section in pe.sections:
  dbcur.execute("INSERT INTO segments (name, fileOffset, fileSize, virtOffset, virtSize, read, write, execute) VALUES (?, ?, ?, ?, ?, 0, 0, 0)", (section.Name, section.PointerToRawData, section.SizeOfRawData, imgBase + section.VirtualAddress, section.Misc_VirtualSize))
#  print section
#  print (section.Name, hex(imgBase + section.VirtualAddress),
#    hex(section.Misc_VirtualSize), section.SizeOfRawData )

pe.parse_data_directories()
print ("Reading imports")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
#  print entry.dll
  for imp in entry.imports:
      dbcur.execute("INSERT INTO labels (offset, labelName, labelType) VALUES (?, ?, ?)", (imp.address, "{}!{}".format(entry.dll.lower(), imp.name), LABEL_IMPORT))
#      print "{}!{} {:x}".format(entry.dll, imp.name, imp.address)

dbcon.commit()
# END OPEN AND PARSE PE FILE ----------------

# HELPER FUNCS ------------
def memoryOffsetToFileOffset(off):
    dbcur.execute("SELECT * FROM segments")
    for r in dbcur.fetchmany():
        if off>=r['virtOffset'] and off<=r['virtOffset']+r['fileSize']:
            return off - int(r['virtOffset']) + int(r['fileOffset'])
    return None

def fileOffsetToMemoryOffset(off):
    dbcur.execute("SELECT * FROM segments")
    for r in dbcur.fetchmany():
        if off>=r['fileOffset'] and off<=r['fileOffset']+r['fileSize']:
            return off - r['fileOffset'] + r['virtOffset']
    return None

# Replace offsets with label names/import names
# Parse full instruction string
re_off = re.compile("0x[0-9a-f]+")
def replaceLabels(inst):
    news = inst
    for o in re_off.findall(inst):
        dbcur.execute("SELECT labelName FROM labels WHERE offset=?", (int(o,16),))
        res = dbcur.fetchall()
        if len(res)>0:
            news = news.replace(o, res[0]['labelName'])
    return news
# END HELPER FUNCS ------------

# Memory map file
fd = file(os.sys.argv[1], 'r+b')
data = mmap.mmap(fd.fileno(), 0)

fileLen = len(data)

# add entry point for beginning
labels[entryPt] = {'type':'sub', 'name':'_start', 'xrefs':[], 'calls_out':[], 'end':0}
tovisit.append(entryPt)

# first pass - Do Disassembly
print "PASS 1"
offset = 0
while True:
    if len(tovisit) == 0: # any more labels to visit?
        break
    offset = tovisit.pop()

    terminalInstruction = False

    # while not finished this label
    while((not disassembly.has_key(offset)) and (not terminalInstruction) and memoryOffsetToFileOffset(offset) != None):
        if offset in tovisit:
            tovisit.remove(offset)

        # decode instructions
        inst = distorm3.Decode(offset, data[memoryOffsetToFileOffset(offset):], distorm3.Decode32Bits)[0]
        #print offset,inst
        ins = inst['mnemonic']
        ops = inst['ops']
        dbcur.execute("INSERT INTO disasm (offset, mnemonic, ops, size, meta) VALUES (?, ?, ?, ?, ?)", (offset, ins, ops, inst['size'], json.dumps(inst)))

        # Is control flow instruction with static destination?
        if (ins.startswith("call") or ins[0] == 'j' or ins.startswith("loop")) and ops.find("0x")!=-1 and ops.find("[")==-1:
            newoff = int(ops[ops.find("0x")+2:],16)

# if not already on tovisit list and not disassembled then add to todo list
            if (not newoff in tovisit) and (not disassembly.has_key(newoff)):
                tovisit.append(newoff)

# add label for called/jmped addr
            if labels.has_key(newoff):
                if not offset in labels[newoff]['xrefs']:
                    labels[newoff]['xrefs'].append(offset)
                    dbcur.execute("INSERT INTO xrefs (fromOffset, toOffset) VALUES(?, ?)", (offset, newoff))
            else:
                labels[newoff] = {}
                labels[newoff]['calls_out'] = []
                labels[newoff]['xrefs'] = [ offset ]
                dbcur.execute("INSERT INTO xrefs (fromOffset, toOffset) VALUES(?, ?)", (offset, newoff))
                labels[newoff]['type'] = ('sub' if ins.startswith('call') else 'lbl')
                dbcur.execute("INSERT INTO labels (offset, labelName, labelType, meta) VALUES (?, ?, ?, ?)", (newoff, getLblName(labels, newoff), LABEL_FUNC if ins.startswith('call') else LABEL_LABEL, json.dumps(labels[newoff])))


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
for off in labels:
#while offset < fileOffsetToMemoryOffset(fileLen):
# check for function start
    if labels[off]['type'] != "sub":
        continue
    print off
    offset = off
    regs = {'ESP': 0, 'EBP': 0 }
    stack = { }
    while True:
        if disassembly.has_key(offset):
            inst = disassembly[offset]
            ins = inst['mnemonic']

# try to keep track of stack
            instd = distorm3.Decompose(offset, data[memoryOffsetToFileOffset(offset):], distorm3.Decode32Bits)[0]
            if ins == "push":
                regs['ESP'] -= 4
            elif ins == "pop":
                regs['ESP'] += 4
            elif ins == "leave":
                regs['ESP'] = regs['EBP']
                regs['ESP'] += 4
            elif ins == "enter":
                print "IMPLEMENT ENTER STACK TRACE***************************"
#                regs['ESP'] -= 4
#                regs['ESP'] -= instd.operands[0].value
                print instd
            else:
                numOps = len(instd.operands)
                if numOps == 2 and instd.operands[0].type == distorm3.OPERAND_REGISTER:
                    val = None
                    reg = instd.operands[0].name

                    # try to resolve value e.g. esp/ebp
                    if instd.operands[1].type == distorm3.OPERAND_IMMEDIATE:
                        val = instd.operands[1].value
                    elif instd.operands[1].type == distorm3.OPERAND_REGISTER and regs.has_key(instd.operands[1].name):
                        val = regs[instd.operands[1].name]

                    if val and regs.has_key(reg):
                        if ins == "sub":
                            regs[reg] -= val

                        if ins == "add":
                            regs[reg] += val

                        if ins == "mov":
                            regs[reg] = val

            if(ins.startswith("call") and inst['ops'].find("0x") != -1 and inst['ops'].find("[") == -1):  # collate calls out of function
                labels[off]['calls_out'].append(int(inst['ops'][inst['ops'].find("0x")+2:],16))
                dbcur.execute("UPDATE labels SET meta=? WHERE offset=?", (json.dumps(labels[off]), off))

            if(ins.startswith("ret")):  #detect function termination
                print "END: ", regs
                if regs['ESP'] != 0:
                    print "***warn stack trace may have failed"
                if not labels[off].has_key('end'):
                    labels[off]['end'] = offset + inst['size']
                    dbcur.execute("UPDATE labels SET meta=? WHERE offset=?", (json.dumps(labels[off]), off))
                break

            offset += inst['size']
        else:
            break

#pass 3 - print
print "PASS 3: Display"
def disassemblyText(disassembly, labels, start, end):
    str = '<pre style="font-family: monospace; font-size: 14px;">'
    inProcLabel = False
    offset = start
    while offset < end:
        if labels.has_key(offset):
            if labels[offset]['type'] == "sub":
               str += "\n\n---STARTPROC---\n"
               inProcLabel = offset
            str += "<span style='color:blue'>%s_%x</span>:\n" % (labels[offset]['type'], offset)

        if disassembly.has_key(offset):
            inst = disassembly[offset]

            ins = replaceLabels(inst['instr'])

            str += "<span style='color:red'>%08x</span>:\t%s\n" % (offset,ins)

            if(ins.startswith("ret") and inProcLabel):  #detect function termination
                str += "<span style='color:blue'>---ENDPROC---  ; sub_%x ; length = %d bytes ; %d calls out</span>\n\n" % (inProcLabel, labels[inProcLabel]['end'] - inProcLabel, len(labels[inProcLabel]['calls_out']))
                inProcLabel = False


            offset += inst['size']
        else:
            fileOffset = memoryOffsetToFileOffset(offset)
            str += "<span style='color:red'>%08x</span>:\tdb 0x%02x %s\n" % (offset, ord(data[fileOffset]), data[fileOffset] if isPrintable(data[fileOffset]) else '')
            offset += 1
    str += "</pre>"
    return str

dtext = disassemblyText(disassembly, labels, 0x401000, 0x402000)
print dtext
print "TOTaL LBLS", len(labels)

#for lbladdr in labels:
#    lbl = labels[lbladdr]
#    if lbl['type'] != 'sub':
#        continue
#    if lbl.has_key('end'):
#        instructions = data[memoryOffsetToFileOffset(lbladdr):memoryOffsetToFileOffset(lbl['end'])]
#        print "%x %d %d %d %s" % (lbladdr, lbl['end'] - lbladdr, len(lbl['calls_out']), len(lbl['xrefs']), md5.new(instructions).hexdigest())

# generate graphviz callgraph
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

#print graphFuncs(labels)
#app = QApplication(sys.argv)
#ex = DisasmWin(dtext, labels)
#sys.exit(app.exec_())

dbcon.commit()
dbcon.close()

