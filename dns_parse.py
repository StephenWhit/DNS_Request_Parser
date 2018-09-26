import sys
import os
import binascii
import codecs


if len(sys.argv) != 2:
	print("Sorry, please input one parameter.")
	sys.exit()

os.chdir("./")

def resolveHex(hexString, fullHex):
	"""This function was a bitch, it first moves through the given hex, byte by byte, looking for 
	pointers and concatenating any it finds onto the partHex string. Then, it takes that string and 
	"cleans" it, getting rid of some of the hex values that do not map to a conventional ASCII value"""
	partHex = ''
	i = len(hexString)
	count = 0
	while count < i:
		if int(hexString[count], 16) >=12:
			partHex = partHex + point(hexString[count:count+4], fullHex)
			count += 2
		else:
			partHex = partHex + hexString[count:count+2]
		count += 2

	tempS = str(binascii.unhexlify(partHex))
	tempS = tempS.replace("b'", "")
	tempS = tempS.replace("'", "")
	tempS = tempS.replace("\\x06", "")
	tempS = tempS.replace("\\x03", ".")
	tempS = tempS.replace("\\t", "	")	#horizontal tab
	tempS = tempS.replace("\\x07", "")	#BEL Char
	tempS = tempS.replace("\\x00", "")	#Null Char
	tempS = tempS.replace("\\x02", ".")	#STX Char
	return tempS

def getType(hexString):
	"""simple getter, takes in hex value for a RRType, and returns the string value of the type"""
	ans = ''
	temp = int(hexString, 16)
	if temp == 1:
		ans = "A"
	elif temp == 2:
		ans = "NS"
	elif temp == 3:
		ans = "MD"
	elif temp == 4:
		ans = "MF"
	elif temp == 5:
		ans = "CNAME"
	elif temp == 6:
		ans = "SOA"
	elif temp == 7:
		ans = "MB"
	elif temp == 8:
		ans = "MG"
	elif temp == 9:
		ans = "MR"
	elif temp == 10:
		ans = "MB"
	elif temp == 11:
		ans = "MG"
	elif temp == 12:
		ans = "PTR"
	elif temp == 13:
		ans = "HINFO"
	elif temp == 14:
		ans = "MINFO"
	elif temp == 15:
		ans = "MX"
	elif temp == 16:
		ans = "TXT"
	elif temp == 255:
		ans = "ANY"
	else:
		ans = "ANY"
	return ans
	
def getClass(hexString):
	"""Simple getter, takes in the hex value of the RR CLass and returns the String Class type"""
	ans = ''
	temp = int(hexString, 16)
	if temp == 0:
		ans = 'RESERVED'
	elif temp == 1:
		ans = 'IN'
	elif temp == 2:
		ans = 'UNASSIGNED'
	elif temp == 3:
		ans = 'CH'
	elif temp == 4:
		ans = 'HS'
	elif temp > 4 and temp < 254:
		ans = 'UNASSIGNED'
	elif temp == 254:
		ans = 'NONE'
	elif temp == 255:
		ans = 'ANY'
	return ans

def point(hexString, fullHex):
	"""takes four hex bits (16 binary bits), lops off the first two since 
	they should be 1s, and jumps to the offest indicated by the ramaining 14.
	returns the value of the thing it jumped to"""
	offset = int(hexString, 16) - 49152
	name, hexString = readTilStop(fullHex[offset*2:])
	return name

def readTilStop(hexString):
	"""reads a given hexString until it reaches a b'00' useful for lots of stuff"""
	name = ""
	while hexString[:2].encode('UTF-8') != b'00' and hexString[:2].encode('UTF-8') !=  b'':
		name += hexString[:2]
		hexString = hexString[2:]
	hexString = hexString[2:]
	return name, hexString

def readQuestion(hexString, fullHex):
	"""Reads a question type and returns its name, class, and type"""
	if int(hexString[0], 16) >= 12:			#if the first part begins with 11
		QName = point(hexString[0:4], fullHex)
		remaining = hexString[4:]
	else:
		QName, remaining = readTilStop(hexString)
	QType = remaining[:4]
	QClass = remaining[4:8]
	remaining = remaining[8:]
	return QName, QType, QClass, remaining

def readRR(hexString, fullHex):
	"""reads an RR, returns it's name, type, class, length, 
	and the hex that should be its data"""
	if int(hexString[0], 16) >= 12:			#if the first part begins with 11
		RName = point(hexString[0:4], fullHex)
		remaining = hexString[4:]
	else:
		RName, remaining = readTilStop(hexString)
	RType = remaining[:4]
	RClass = remaining[4:8]
	TTL = remaining[8:16]
	RDLen = remaining[16:20]
	RDLen  = int(RDLen, 16) * 2
	RData = remaining[20:20+RDLen]
	remaining = remaining[20+RDLen:]
	return RName, RType, RClass, TTL, RDLen, RData, remaining

def readHeader(hexString, dataHex, fullHex):
	"""this breaks down the header and assigns their values to easy-to-print variables
		and sets the counts for the data to follow"""
	Quer = ""
	TruncFlag = ""
	RecurDes = ""
	RecurAvail = ""
	error = ""

	#ID parsing ---------------------
	ID = hexString[:4]

	#QR, Opcode, AA, TC, and RD parsing --------------
	FS = hexString[4:6]
	temp = int(FS, 16)
	binary = format(temp, '0>8b')

	if str(binary[0]) == "0":
		MessageType = "QUERY"
		Quer = "qr "
	else:
		MessageType = "RESPONSE"

	OC = binary[1:5]
	OC = int(OC, 2)
	if OC == 0:
		opcode = "QUERY"
	elif OC == 1:
		opcode = "IQUERY"
	elif OC == 2:
		opcode = "STATUS"
	elif OC == 3:
		opcode = "(reserved)"
	elif OC == 4:
		opcode = "NOTIFY"
	elif OC == 5:
		opcode = "UPDATE"

	Authority = binary[5]
	if str(binary[6]) == "1":
		TruncFlag = "tc "
	if str(binary[7]) == "1":
		RecurDes = "rd "

	#RA, Z, and RCode parsing ------------------
	LS = hexString[6:8]
	temp = int(LS, 16)
	binary = format(temp, '0>8b')
	if str(binary[0]) == "1":
		RecurAvail = "ra"
	RCode = binary[4:]
	RCode = int(RCode, 2)
	if RCode == 0:
		error = "NOERROR"
	elif RCode == 1:
		error = "FORMATERROR"
	elif RCode == 2:
		error = "SERVERFAILURE"
	elif RCode == 3:
		error = "NAMEERROR"
	elif RCode == 4:
		error = "NOTIMPLEMENTED"
	elif RCode == 5:
		error = "REFUSED"
	elif RCode == 6:
		error = "YXDOMAIN"
	elif RCode == 7:
		error = "YXRRSET"
	elif RCode == 8:
		error = "NXRRSET"
	elif RCode == 9:
		error = "NOTAUTH"
	elif RCode == 10:
		error = "NOTZONE"

	#Question, Answer, Authority, and Additional Count -----------
	QD = hexString[8:12]
	QD = int(QD, 16)

	AN = hexString[12:16]
	AN = int(AN, 16)

	NS = hexString[16:20]
	NS = int(NS, 16)

	AR = hexString[20:]
	AR = int(AR, 16)

	#Printing out the Header info
	print(";; ->>HEADER<<- opcode: " + opcode + ", status: " + error + ", id: " + ID)
	print(";; flags: " + Quer + TruncFlag + RecurDes + RecurAvail + "; QUERY: " + str(QD) + 
		", ANSWER: " + str(AN) + ", AUTHORITY: " + str(NS) + ", ADDITIONAL: " + str(AR) + "\n")

	#Looping the Question parser ------------
	print(";; QUESTION SECTION: ")
	temp = QD
	while (temp > 0):
		QName, QType, QClass, remaining = readQuestion(dataHex, fullHex)
		print(resolveHex(QName, fullHex) + "		" + getClass(QClass) + "	" + getType(QType))
		temp -= 1

	#Looping the Answer section
	if AN >= 1:
		print("\n;; ANSWER SECTION:")

	temp = AN
	while (temp > 0):
		RName, RType, RClass, TTL, RDLen, RData, remaining = readRR(remaining, fullHex)
		if getType(RType) == "A":
			RData = str(int(RData[:2], 16))+"."+str(int(RData[2:4], 16))+"."+str(int(RData[4:6], 16))+"."+str(int(RData[6:], 16)) 
		elif getType(RType) == "NS":
			RData = str(resolveHex(RData, fullHex))
		elif getType(RType) == "CNAME":
			RData = str(resolveHex(RData, fullHex))
		elif getType(RType) == "ANY":
			RData = ""
		else:
			RData = ""

		print(resolveHex(RName, fullHex) + "     " + str(int(TTL, 16)) + "	" + getClass(RClass)
		 + "	" + getType(RType) + "	" + RData)

		temp -= 1

	#Looping the Authority Section -----------------
	if NS >= 1:
		print("\n;;AUTHORITY SECTION:")
	temp = NS
	while (temp > 0):
		AName, AType, AClass, TTL, ALen, AData, remaining = readRR(remaining, fullHex)
		if getType(AType) == "A":
			AData = str(int(AData[:2], 16))+"."+str(int(AData[2:4], 16))+"."+str(int(AData[4:6], 16))+"."+str(int(AData[6:], 16)) 
		elif getType(AType) == "NS":
			AData = str(resolveHex(AData, fullHex))
		elif getType(AType) == "CNAME":
			AData = str(resolveHex(AData, fullHex))
		elif getType(AType) == "ANY":
			AData = ""
		else:
			AData = ""

		print(resolveHex(AName, fullHex) + "	" + str(int(TTL, 16)) + "	" + getClass(AClass)
		 + "	" + getType(AType) + "	" + AData)

		temp -= 1
	return


while True:
	fullpath = sys.argv[1]
	f = open(fullpath,'rb')
	weirdHex = f.read()					#reading the file and saving it as respBod
	f.close()

	normHex = weirdHex.hex()
	readHeader(normHex[:24], normHex[24:], normHex)
	break;

"""
$ dig example.com any
; <<>> DiG 9.6.1 <<>> example.com any
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4016
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;example.com.                   IN      ANY

;; ANSWER SECTION:
example.com.            172719  IN      NS      a.iana-servers.net.
example.com.            172719  IN      NS      b.iana-servers.net.
example.com.            172719  IN      A       208.77.188.166
example.com.            172719  IN      SOA     dns1.icann.org. hostmaster.icann.org. 2007051703 7200 3600 1209600 86400

;; Query time: 1 msec
;; SERVER: ::1#53(::1)
;; WHEN: Wed Aug 12 11:40:43 2009
;; MSG SIZE  rcvd: 154
"""