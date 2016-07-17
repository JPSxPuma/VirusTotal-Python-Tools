#!/usr/bin/python

import sys
import urllib2
import urllib
import json
from PyQt4.QtCore import *
from PyQt4.QtGui import *

VIRUSTOTAL_API2_KEY = ''
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"


class Form(QDialog):
	def __init__(self,parent=None):
		super(Form,self).__init__(parent)

		self.hash_label = QLabel("Hash: ")
		self.lineedit = QLineEdit("paste in a file hash")
		self.result_label = QLabel("Results: ")
		self.scanner_label = QLabel("<b><font color=green>0/0</font></b>")
		self.setGeometry(200,200,600,50)

		grid = QGridLayout()
		grid.addWidget(self.hash_label,0,0)
		grid.addWidget(self.lineedit,0,1)
		grid.addWidget(self.result_label,1,0)
		grid.addWidget(self.scanner_label,1,1)

		self.setLayout(grid)

		self.connect(self.lineedit,SIGNAL("returnPressed()"), self.updateUi)

	def updateUi(self):
		self.scanner_label.setText(self.VTScan())

	def VTScan(self):
		searchTerm = self.lineedit.text()
		webForms = {'resource':searchTerm,'apikey':VIRUSTOTAL_API2_KEY}
		req = urllib2.Request(VIRUSTOTAL_REPORT_URL,urllib.urlencode(webForms))

		hRequest = urllib2.urlopen(req, timeout=15)
		data = hRequest.read()
		data = json.loads(data)
		pos = data['positives']
		total = data['total']

		if pos > 0:
			return "<b><font color=red>%s / %s</font></b>" % (pos, total)
		else:
			return "<b><font color=green>%s / %s</font></b>" % (pos, total)

app = QApplication(sys.argv)
form = Form()
form.show()
app.exec_()


