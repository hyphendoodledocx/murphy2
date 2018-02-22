from socket import *
listener=socket(AF_INET,SOCK_STREAM)
listener.bind(("110.76.70.77",9999))
listener.listen(5)
c,a=listener.accept()
print "Received connection from: "+a[0]+":"+str(a[1])

while True:
	data=c.recv().decode()
	print(data)
		