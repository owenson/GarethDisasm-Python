class DisasmDb(object):
    """docstring for DisasmDb"""
    def __init__(self):
        super(DisasmDb, self).__init__()
        self.labels = {}
        self.disassembly = {}

    def getDisassembly(offset):
        return self.disassembly[offset]

    def putDisassembly(offset, data):
        self.disassembly[offset] = data

    def putLabel(offset, name, ty):
        if labels.has_key(newoff):
            return
        labels[offset] = {}
        labels[offset]['calls_out'] = []
        labels[offset]['xrefs'] = [ ]
        labels[offset]['type'] = ty

    def addLabelXref(label, xref):





