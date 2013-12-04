import os,md5
from pydasm import *

labels = {}
tovisit = []
disassembly = {}

BASE_ADDR = 0x0;

def memoryOffsetToFileOffset(off):
	global BASE_ADDR;
	return off - BASE_ADDR;

def fileOffsetToMemoryOffset(off):
	global BASE_ADDR;
	return off + BASE_ADDR;

  
fd = file(os.sys.argv[1], 'rb')
data = fd.read()
fd.close()
  
fileLen = len(data)

print "PASS 1"

# first pass
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

        inst = get_instruction(data[offset:], MODE_16)

        if not inst:
            print "fail"
            break

        ins = get_instruction_string(inst, FORMAT_INTEL, offset)

        if (ins.startswith("call") or ins[0] == 'j' or ins.startswith("loop")) and inst.op1.type == OPERAND_TYPE_IMMEDIATE:
            newoff = int(get_operand_string(inst, 0,FORMAT_INTEL, offset)[2:],16)

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
            offset += inst.length;

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
        ins = get_instruction_string(inst, FORMAT_INTEL, offset)

        if(ins.startswith("call") and inProcLabel):  # collate calls out of function
            labels[inProcLabel]['calls_out'].append(int(get_operand_string(inst, 0,FORMAT_INTEL, offset)[2:],16))        

        if(ins.startswith("ret") and inProcLabel):  #detect function termination
            if not labels[inProcLabel].has_key('end'):
                labels[inProcLabel]['end'] = offset + inst.length
            inProcLabel = False
        
        offset += inst.length
    else:
        offset += 1

#pass 3 - print
print "PASS 3: Display"
inProcLabel = False
offset = BASE_ADDR
while offset < fileOffsetToMemoryOffset(fileLen):
    if labels.has_key(offset):
        if labels[offset]['type'] == "sub":
           print
           print "---STARTPROC---" 
           inProcLabel = offset
        print "%s_%x:" % (labels[offset]['type'], offset)
    
    if disassembly.has_key(offset):
        inst = disassembly[offset]

        ins = get_instruction_string(inst, FORMAT_INTEL, offset)
        
        print "%08x:\t%s" % (offset,ins)        
                
        if(ins.startswith("ret") and inProcLabel):  #detect function termination
            print "---ENDPROC---  ; sub_%x ; length = %d bytes ; %d calls out" % (inProcLabel, labels[inProcLabel]['end'] - inProcLabel, len(labels[inProcLabel]['calls_out']))
            print
            inProcLabel = False
        
        
        offset += inst.length
    else:
        print "%08x:\tdb 0x%02x" % (offset, ord(data[offset]))
        offset += 1

print "TOTaL LBLS", len(labels)

for lbladdr in labels:
    lbl = labels[lbladdr]
    if lbl['type'] != 'sub':
        continue
    if lbl.has_key('end'):
        instructions = data[memoryOffsetToFileOffset(lbladdr):memoryOffsetToFileOffset(lbl['end'])]
        print "%x %d %d %d %s" % (lbladdr, lbl['end'] - lbladdr, len(lbl['calls_out']), len(lbl['xrefs']), md5.new(instructions).hexdigest())
