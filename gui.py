#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from PyQt4.QtGui import *


class Example(QWidget):

    def __init__(self):
        super(Example, self).__init__()

        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 250, 150)
        self.setWindowTitle('Icon')
        hbox = QHBoxLayout(self)
        combo = QListView(self)
        model = QStandardItemModel(combo)
        for i in range(10):
            item = QStandardItem(str(i))
            model.appendRow(item)
        combo.setModel(model)
        disasm = QTextEdit(self)
        hbox.addWidget(combo)
        hbox.addWidget(disasm)
        self.setLayout(hbox)
        #combo.resize(200,combo.height())
        self.showMaximized()
        combo.setFixedSize(200,self.height())

def main():

    app = QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
