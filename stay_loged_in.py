import hashlib
#18.06.2013


#if Checkbox Safe my data is checked:
hash_user = hashlib.md5()
hash_password = hashlib.md5()
password_encoded = password.encode('utf-8')
user_encoded = user.encode('utf-8')
hash_password.update(password_encoded) #Give Password here
hash_user.update(user_encoded) #Give User here
hash_passord_output = hash_password.hexdigest()
hash_user_output = hash_user.hexdigest()

save_info_user = open('login_data_user.info', 'w')
safe_info.write(hash_user_output)
save_info_password = open('login_data_password.info', 'w')
safe_info.write(hash_password_output)


#On Startup checks if the files are there
try:
  with open('./login_data_user.info'): pass
	auto_login = true
except IOError: pass
	auto_login = false

if(auto_login = true):
    open_info_user = open('login_data_user.info', 'r')
    open_info_password = open('login_data_password.info', 'r')
    # send the info and request a confirmation from the server if not right send user to Login screen
else:
    #Login screen
