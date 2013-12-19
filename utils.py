
def getLblName(labels, off):
    return "{}_{:x}".format(labels[off]['type'], off) if not labels[off].has_key( 'name' ) else labels[off]['name']

def isPrintable(c):
    return ord(c)>=0x20 and ord(c)<0x80
