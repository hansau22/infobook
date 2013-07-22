from datetime import datetime
import time
from libinfoclient import SocketHandler
import sys
import time
from PyQt4 import QtCore, QtGui, uic
import PyQt4.uic

## GUI

MainWindowForm, MainWindowBase = PyQt4.uic.loadUiType('LogInScreen_v1.1.ui')

class MainWindow(MainWindowBase, MainWindowForm):
    def __init__(self, parent = None):
        super(MainWindow, self).__init__(parent)
        
        # setup the ui
        self.setupUi(self)


def login():
    user = window.lineEdit_3.text()
    password = window.lineEdit.text()
    stayLogedIn = window.checkBox.isChecked() 



if ( __name__ == '__main__' ):
    app = None
    if ( not app ):
        app = QtGui.QApplication([])

    window = MainWindow()
    window.show()
    
    window.connect(window.pushButton_2, QtCore.SIGNAL("clicked()"), app.quit)
    window.connect(window.pushButton, QtCore.SIGNAL("clicked()"), login)


    if ( app ):
        app.exec_()

## Other Stuff

port = 32325

try:
    so = SocketHandler('localhost', port)
except RuntimeError as err:
    print err
if not so.auth(None, None, True):
    print "error in auth"
    exit()

if so.write_group_message("meop", str(datetime.time(datetime.now()))):
    print "geht"
else:
    print "fail"


messages = so.get_messages("1")
print messages
counter = 0


# while counter < 5:
#   if isinstance(messages, bool):
#       print "error in getting messages"
#       counter += 1
#       time.sleep(3)
#       messages = so.get_messages("1")
#       time.sleep(3)
#       so.write_group_message("meop", str(datetime.time(datetime.now())))


#   else:
#       for item in messages:
#           print unicode(item[0]) + ":" + unicode(item[1])
#           exit()

while counter < 5:
    print so.write_group_message("moep", str(datetime.time(datetime.now())))
    time.sleep(3)
    print so.get_messages("1")
    time.sleep(3)
    counter += 1
