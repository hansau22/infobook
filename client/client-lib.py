#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
import time
from libinfoclient import SocketHandler
import sys

#port = int(sys.argv[1])
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
# 	if isinstance(messages, bool):
# 		print "error in getting messages"
# 		counter += 1
# 		time.sleep(3)
# 		messages = so.get_messages("1")
# 		time.sleep(3)
# 		so.write_group_message("meop", str(datetime.time(datetime.now())))


# 	else:
# 		for item in messages:
# 			print unicode(item[0]) + ":" + unicode(item[1])
# 			exit()

while counter < 5:
	print so.write_group_message("moep", str(datetime.time(datetime.now())))
	time.sleep(3)
	print so.get_messages("1")
	time.sleep(3)
	counter += 1
