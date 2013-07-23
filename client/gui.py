from datetime import datetime
import time
from libinfoclient import SocketHandler
import sys
import time
from os.path import exists
from PyQt4 import QtCore, QtGui, uic
import PyQt4.uic

window_def = "registration"


port = 32325

try:
    so = SocketHandler('localhost', port)
except RuntimeError as err:
    print err

if exists("login.dat") == True:
    print("auth file is there")
    if not so.auth_stayLogedIn():
        print "error in auth with file"
        exit()
    else:
        window_def = "registration"
## GUI
MainWindowForm_Login, MainWindowBase_Login = PyQt4.uic.loadUiType('LogInScreen_v1.1.ui')

MainWindowForm_Home, MainWindowBase_Home = PyQt4.uic.loadUiType('Homescreen_v1.2.ui')

MainWindowForm_Chat, MainWindowBase_Chat = PyQt4.uic.loadUiType('Chatfenster_v1.1.ui')


MainWindowForm_Reg, MainWindowBase_Reg = PyQt4.uic.loadUiType('Registration_v1.ui')


class MainWindow_Login(MainWindowBase_Login, MainWindowForm_Login):
    def __init__(self, parent = None):
        super(MainWindow_Login, self).__init__(parent)
        
        # setup the ui
        self.setupUi(self)

class MainWindow_Normal(MainWindowBase_Home, MainWindowForm_Home):
    def __init__(self, parent = None):
        super(MainWindow_Normal, self).__init__(parent)
        
        self.button = QtGui.QPushButton("test button", self)
        self.button.move(20, 200)
        # setup the ui
        self.setupUi(self)

class MainWindow_Chat(MainWindowBase_Chat, MainWindowForm_Chat):
    def __init__(self, parent = None):
        super(MainWindow_Chat, self).__init__(parent)
        
        # setup the ui
        self.setupUi(self)

class MainWindow_Registration(MainWindowBase_Reg, MainWindowForm_Reg):
    def __init__(self, parent = None):
        super(MainWindow_Registration, self).__init__(parent)
        
        # setup the ui
        self.setupUi(self)
def login_func():
    user = str(window.lineEdit_3.text())
    password = str(window.lineEdit.text())
    stayLogedIn = window.checkBox.isChecked()
    #port = int(sys.argv[1])
    port = 32325

    try:
        so = SocketHandler('localhost', port)
    except RuntimeError as err:
        print err



    if not so.auth(None, None, True):
        print "error in auth"
        exit()
    else:
        window_def = "normal"

def reg_func():
    user = str(window.username.text())
    password = str(window.password.text())
    conf_password = str(window.confirm_password.text())
    if password == conf_password and password != "" and user != "":
        if not so.add_new_user(user, password):
            window.label_error.setText("Please Try again something went wrong")
        else:
            window.label_error.setText("User added successfuly")

    else:
        window.label_error.setText("Please Try again something went wrong")

def chat_text_func():
    text = str(window.lineEdit.text())
    receiver = "test"
    so.write_message(receiver, text)

def back_to_normal():
    window_def = "normal"
    global window
    window = MainWindow_Normal()
    window.show()


def chat_file_func():
    filename = QtGui.QFileDialog.getOpenFileName(self, 'Open File', '.')
    fname = open(filename)
    data = fname.read()
    self.textEdit.setText(data)
    fname.close() 

    try:
        so = SocketHandler('localhost', port)
    except RuntimeError as err:
        print err

    if not so.auth(None, None, True):
        print "error in auth"
        exit()
    so.write_message(receiver, text)

    #if so.write_group_message("meop", str(datetime.time(datetime.now()))):
    #   print "geht"
    #else:
    #   print "fail"


    #messages = so.get_messages("1")
    #print messages
    #counter = 0


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

    # while counter < 5:
    #   print so.write_group_message("moep", str(datetime.time(datetime.now())))
    #   time.sleep(3)
    #   print so.get_messages("1")
    #   time.sleep(3)
    #   counter += 1


    """
    filestring = so.request_file()
    print filestring
    if filestring:
        try:
            ret = so.upload_file(filestring, "/home/julian/asdf", "asdf")
            ret = so.get_file(filestring)
            if not ret:
                print "file receiving worked"
        except RuntimeError as error:
            print error
    """



if window_def == "login":
    if ( __name__ == '__main__' ):
        app = None
        if ( not app ):
            app = QtGui.QApplication([])
        global window
        window = MainWindow_Login()
        window.show()
            
        window.connect(window.pushButton_2, QtCore.SIGNAL("clicked()"), app.quit)
        window.connect(window.pushButton, QtCore.SIGNAL("clicked()"), login_func)


        if ( app ):
            app.exec_()


if window_def == "normal":
    if ( __name__ == '__main__' ):
        app = None
        if ( not app ):
            app = QtGui.QApplication([])
        
        global window
        window = MainWindow_Normal()
        window.show()

        if ( app ):
            app.exec_()


if window_def == "registration":
    if ( __name__ == '__main__' ):
        
        if ( not QtGui.QApplication.instance() ):
            app = QtGui.QApplication([])
        global window
        window = MainWindow_Registration()
        window.show()     

        

        window.connect(window.cancel, QtCore.SIGNAL("clicked()"), back_to_normal)
        window.connect(window.register_2, QtCore.SIGNAL("clicked()"), reg_func)

        app.exec_()


if window_def == "chat":
    if ( __name__ == '__main__' ):
        app = None
        if ( not app ):
            app = QtGui.QApplication([])
        global window
        window = MainWindow_Chat()
        window.show()

        window.connect(window.pushButton, QtCore.SIGNAL("clicked()"), chat_text_func)

        if ( app ):
            app.exec_()


## Other Stuff