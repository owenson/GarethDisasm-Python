#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from PyQt4.QtGui import *
from utils import *

class DisasmWin(QWidget):

    def __init__(self, disasm, labels):
        super(DisasmWin, self).__init__()
        self.disasm = disasm
        self.labels = labels

        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 250, 150)
        self.setWindowTitle('Icon')
        hbox = QHBoxLayout(self)
        combo = QListView(self)
        model = QStandardItemModel(combo)
        for i in sorted(self.labels):
            if self.labels[i]['type'] == 'sub':
                item = QStandardItem(getLblName(self.labels, i))
                item.setEditable(False)
                model.appendRow(item)
        combo.setModel(model)
        disasm = QTextEdit(self)
        disasm.setHtml(self.disasm)
        hbox.addWidget(combo)
        hbox.addWidget(disasm)
        self.setLayout(hbox)
        #combo.resize(200,combo.height())
        self.showMaximized()
        combo.setFixedSize(200,self.height())


