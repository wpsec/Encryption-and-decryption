# coding=utf-8
import hmac
import requests
import optparse
import json
import base64
import hashlib
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from pyDes import des, PAD_PKCS5, CBC
import binascii
import urllib.parse as up

def decodes(decode,value):
	decode_dict = \
		{
			'MD5': 1, 'md5': 1,
			'MD4': 2, 'md4': 2,
			'SHA512': 3, 'sha512': 3,
			'SHA1': 4, 'sha1': 4,
			'SHA384': 5, 'sha384': 5,
			'SHA224': 6, 'sha224': 6,
			'SHA256': 7, 'sha256': 7,
			'BASE64': 8, 'base64': 8,
			'AES': 9, 'aes': 9,
			'DES': 10, 'des': 10,
			'URL':11, 'url': 11
		}
	number = None
	if(decode in decode_dict):
		for i in decode_dict:
			if(i == decode):
				number = decode_dict[i]
	else:
		print('暂不支持此解密')
		exit(0)
	if(number < 8):
		for number in range(1,8):
			dectype = decode.lower()
			value = decsha(value,dectype)
			return value
	elif(number == 8):
		value = decbase64(value)
		return value
	elif(number == 9):
		value = decaes(value)
		return value
	elif(number == 10):
		value = decdes(value)
		return value
	elif(number == 11):
		value = decurl(value)
		return value

def decsha(value,dectype):
	print(dectype)
	for i in range(1,int(9e10)):
		now_sha = hashlib.new(str(dectype), str(i).encode(encoding='utf-8')).hexdigest()
		if str(value) == now_sha:
			print('decode: {} {} : {}'.format(str(i),dectype,str(now_sha)))
			return i
	else:
		print('无匹配')
		exit(0)

def decbase64(value):
	value = value.encode(encoding='utf-8')
	try:
		value = base64.b64decode(value).decode('utf-8')
		return value
	except:
		print('格式错误')
		exit(0)

def decaes(value):
	key = input('请输入key: ')
	iv = input('请输入偏移值: ')
	mode = AES.MODE_CBC
	try:
		cryptos = AES.new(key.encode(encoding='utf-8'), mode, iv.encode(encoding='utf-8'))
		value = cryptos.decrypt(a2b_hex(value.encode(encoding='utf-8')))
		value = bytes.decode(value).rstrip('\0')
		return value
	except ValueError:
		print('密钥或者偏移错误')
		exit(0)

def decdes(value):
	key = input('请输入key: ')
	iv = input('请输入偏移: ')
	try:
		key = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
		value = key.decrypt(binascii.a2b_hex(value), padmode=PAD_PKCS5).decode('utf-8')
		return value
	except ValueError:
		print('密钥或者偏移错误')
		exit(0)
def decurl(value):
	value = up.unquote(value)
	return value

def encodes(enable,value):
	enable_dict = \
		{
			'MD5': 1, 'md5': 1,
			'MD4': 2, 'md4': 2,
			'SHA512': 3, 'sha512': 3,
			'SHA1': 4, 'sha1': 4,
			'SHA224': 5, 'sha224': 5,
			'SHA256': 6, 'sha256': 6,
			'SHA384': 7, 'sha384': 7,
			'SHA3-512': 8, 'sha3-512': 8,
			'BLAKE2B': 9, 'blake2b': 9,
			'BLAKE2S': 10, 'blake2s': 10,
			'SHA3-224': 11, 'sha3-224': 11,
			'SHA3-256': 12, 'sha3-256': 12,
			'SHA3-384': 13, 'sha3-384': 13,
			'BASE64': 14, 'base64': 14,
			'SHAKE-128': 15, 'shake-128': 15,
			'SHAKE-256': 16, 'shake-256': 16,
			'AES': 17, 'aes': 17,
			'DES': 18, 'des': 18,
			'HMAC': 19, 'hmac': 19,
			'URL': 20, 'url': 20,

		}
	number = None
	if (enable in enable_dict):
		for i in enable_dict:
			if(i == enable):
				number = enable_dict[i]
	else:
		return 'NO'
	if(number < 15):
		for number in range(1,15):
			value = encmisc(enable,value)
			return value

	if(number == 15):
		length = int(input('请输入长度(Bits): '))
		length /= 8
		value = hashlib.shake_128(str(value).encode(encoding='utf-8')).hexdigest(int(length))
		return value
	elif(number == 16):
		length = int(input('请输入长度(Bits): '))
		length /= 8
		value = hashlib.shake_256(str(value).encode(encoding='utf-8')).hexdigest(int(length))
		return value
	elif(number == 17):
		value = str(encaes(value))
		return value
	elif(number == 18):
		value = encdes(value)
		return value
	elif(number == 19):
		value = enchmac(value)
		return value
	elif(number == 20):
		value = encurl(value)
		return value
def encmisc(enctype,value):
	value = hashlib.new(enctype,str(value).encode(encoding='utf-8')).hexdigest()
	return value
def encaes(value):
	key = input('请输入key: ').encode(encoding='utf-8')
	iv = input('请输入偏移: ').encode()
	mode = AES.MODE_CBC
	if len(value.encode(encoding='utf-8')) % 16:
		add = 16 - (len(value.encode(encoding='utf-8')) % 16)
	else:
		add = 0
	value = value + ('\0' * add)
	value = value.encode(encoding='utf-8')
	try:
		cryptos = AES.new(key, mode, iv)
		value = cryptos.encrypt(value)
		value = b2a_hex(value).decode('utf-8')
		return value
	except ValueError:
		print('偏移量 或者 key 错误')
		exit(0)

def encdes(value):
	key = input('请输入key: ')
	iv = input('请输入偏移: ')
	try:
		key = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
		value = key.encrypt(value, padmode=PAD_PKCS5)
		value = binascii.b2a_hex(value).decode('utf-8')
		return value
	except ValueError:
		print('偏移量 或者 key 错误')
		exit(0)
def enchmac(value):
	key = input('请输入key: ')
	hashtype = input('请输入加密类型\n sha1 , sha224 , sha256 , sha384 , sha512 , md5 \n默认 MD5: ')
	if(hashtype == '') or (hashtype == 'md5'):
		value = hmac.new(key.encode(encoding='utf-8'),value.encode(encoding='utf-8'),hashlib.md5)
	elif(hashtype == 'sha1') or (hashtype == 'SHA1'):
		value = hmac.new(key.encode(encoding='utf-8'), value.encode(encoding='utf-8'), hashlib.sha1)
	elif(hashtype == 'sha224') or (hashtype == 'SHA224'):
		value = hmac.new(key.encode(encoding='utf-8'), value.encode(encoding='utf-8'), hashlib.sha224)
	elif(hashtype == 'sha256') or (hashtype == 'SHA256'):
		value = hmac.new(key.encode(encoding='utf-8'), value.encode(encoding='utf-8'), hashlib.sha256)
	elif(hashtype == 'sha384') or (hashtype == 'SHA384'):
		value = hmac.new(key.encode(encoding='utf-8'), value.encode(encoding='utf-8'), hashlib.sha384)
	elif(hashtype == 'sha512') or (hashtype == 'SHA512'):
		value = hmac.new(key.encode(encoding='utf-8'), value.encode(encoding='utf-8'), hashlib.sha512)
	else:
		value = hmac.new(key.encode(encoding='utf-8'),value.encode(encoding='utf-8'),hashlib.md5)
	value.digest()
	value = value.hexdigest()
	return value

def encurl(value):
	value = up.quote(value)
	return value

def api(encode,value):
	encode_dict = \
		{
			'MD4': 1, 'md4': 1,
			'MD5': 2, 'md5': 2,
			'SHA1': 3, 'sha1': 3,
			'SHA2': 4, 'sha2': 4,
			'SHA256': 4, 'sha256': 4,
			'HighwayHash256': 5, 'highwayhash256': 5,
			'Highway256': 5, 'highway256': 5,
			'HighwayHash64': 6, 'highwayhash64': 6,
			'Highway64': 6, 'highway64': 6,
			'HighwayHash128': 7, 'highwayhash128': 7,
			'Highway128': 7, 'highway128': 7,
			'SHA384': 8, 'sha384': 8,
			'SHA512': 9, 'sha512': 9,
			'SHA512-256': 10, 'sha512-256': 10,
			'SHA3-256': 11, 'sha3-256': 11,
			'SHA3-384': 12, 'sha3-384': 12,
			'SHA3-512': 13, 'sha3-512': 13
		}
	number = None
	if (encode in encode_dict):
		for i in encode_dict:
			if(i == encode):
				number = encode_dict[i]
	else:
		return 'NO'
	if(number == 1):
		url = None
		digestformat = input("当前为md4，请输入格式: base64 or hex : ")
		if(digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/md4/{}?value={}'.format(digestformat,str(value))
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/md4/{}?value={}'.format(digestformat,str(value))
		method = 'get'
		value = api_call(url,method)
		print('编码类型: ' + digestformat)
		return value

	elif(number == 2):
		url = None
		digestformat = input("当前为md5，请输入格式: base64 or hex : ")
		if(digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/md5/{}?value={}'.format(digestformat,value)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/md5/{}?value={}'.format(digestformat,value)
		method = 'get'
		value = api_call(url,method)
		print('编码类型: ' + digestformat)
		return value

	elif(number == 3):
		url = None
		digestformat = input("当前为sha1，请输入格式: base64 or hex : ")
		if(digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/sha1/{}?value={}'.format(digestformat,value)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/sha1/{}?value={}'.format(digestformat, value)
		method = 'get'
		value = api_call(url,method)
		print('编码类型: ' + digestformat)
		return value

	elif(number == 4):
		url = None
		digestformat = input("当前为sha256，请输入格式: base64 or hex : ")
		if(digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/sha256/{}?value={}'.format(digestformat,value)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/sha256/{}?value={}'.format(digestformat, value)
		method = 'get'
		value = api_call(url,method)
		print('编码类型: ' + digestformat)
		return value

	elif(number == 5):
		hashkey = input("当前为HighwayHash256，请输入haskkey32，随机生成输入 auto : ")
		if(hashkey == ''):
			hashkey = 'auto'
		url = 'https://api.hashify.net/hash/highway/base64url'
		value = HighwayHash(url,hashkey)
		return value

	elif(number == 6):
		hashkey = 'highway64'
		url = None
		digestformat = input("当前为highway64，请输入格式: base64 or hex or base32: ")
		if(digestformat == 'base64') or (digestformat == 'hex') or (digestformat == 'base32'):
			url = 'https://api.hashify.net/hash/highway-64/{}'.format(digestformat)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/highway-64/{}'.format(digestformat)
		value = HighwayHash(url, hashkey)
		return value

	elif(number == 7):
		hashkey = 'highway128'
		url = None
		digestformat = input("当前为highway128，请输入格式(默认为hex): base64 : ")
		if(digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/highway-128/{}'.format(digestformat)
			return value
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/highway-128/{}'.format(digestformat)
		value = HighwayHash(url, hashkey)
		return value

	elif(number == 8):
		url = None
		digestformat = input("当前为sha384，请输入格式: base64 or hex : ")
		if(digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/sha384/{}?value={}'.format(digestformat,value)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/sha384/{}?value={}'.format(digestformat,value)
		method = 'get'
		value = api_call(url,method)
		print('编码类型: ' + digestformat)
		return value

	elif(number == 9):
		url = None
		digestformat = input("当前为sha512，请输入格式: base64 or hex : ")
		if (digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/SHA512/{}?value={}'.format(digestformat,value)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/SHA512/{}?value={}'.format(digestformat,value)
		method = 'get'
		value = api_call(url,method)
		print('编码类型: ' + digestformat)
		return value

	elif(number == 10):
		url = None
		digestformat = input("当前为sha512-256，请输入格式: base64 or hex : ")
		if (digestformat == 'base64') or (digestformat == 'hex'):
			url = 'https://api.hashify.net/hash/sha512-256/{}?value={}'.format(digestformat, value)
		elif(digestformat == ''):
			digestformat = 'hex'
			url = 'https://api.hashify.net/hash/sha512-256/{}?value={}'.format(digestformat, value)
		method = 'get'
		value = api_call(url, method)
		print('编码类型: ' + digestformat)
		return value

def HighwayHash(url,hashkey):
	if(hashkey == 'highway64') or (hashkey == 'highway128'):
		headers = {'Content-Type': 'text/plain', 'charset': 'utf-8', 'X-Hashify-Key': 'random'}
		r = requests.post(str(url), headers=headers, timeout=15)
		conn = r.content.decode('utf-8')
		info = conn
		info = json.loads(info)
		enc = info['DigestEnc']
		print('编码类型：' + str(enc))
		value = info['Digest']
		return value

	headers = None
	if(hashkey == 'auto'):
		hashkey32 = create_key(32)
		print('当前hashkey32: ' +  str(hashkey32))
		headers = {'Content-Type': 'text/plain', 'charset': 'utf-8', 'X-Hashify-Key': str(hashkey32)}
	elif(hashkey != 'auto') and (len(hashkey) / 2 == 32):
		headers = {'Content-Type': 'text/plain', 'charset': 'utf-8', 'X-Hashify-Key': str(hashkey)}
	else:
		print('长度错误')
		exit(0)
	r = requests.post(str(url), headers=headers, timeout=15)
	conn = r.content.decode('utf-8')
	info = conn
	info = json.loads(info)
	value = info['Digest']

	return value



def create_key(len):
	url = 'https://api.hashify.net/keygen/{}'.format(len)
	r = requests.get(str(url))
	conn = r.content.decode('utf-8')
	info = conn
	info = json.loads(info)
	keyhash = info['KeyHex']
	return keyhash


def api_call(url,method):
	r = None
	if (method == 'get'):
		headers = {'user-agent': 'Mozilla/5.0'}
		r = requests.get(str(url), headers=headers, timeout=15)
	elif (method == 'post'):
		headers = {'Content-Type': 'application/raw'}
		r = requests.post(str(url), headers=headers, timeout=15)
	conn = r.content.decode('utf-8')
	info = conn
	info = json.loads(info)
	try:
		value = info['Digest']
		return value
	except:
		print('异常错误')
		exit(0)

def status():
	web_status = 'https://api.hashify.net/status'
	headers = {'user-agent': 'Mozilla/5.0'}
	r = requests.get(str(web_status), headers=headers, timeout=30)
	http_status = r.status_code
	if(http_status == 400):
		print ('网络错误')
		exit(0)
	elif(http_status == 301):
		print ('跳转')
		exit(0)
	elif(http_status == 200):
		conn = r.content.decode('utf-8')
		info = conn
		info = json.loads(info)
		h_status = info['status']
		return h_status


def main():
	parser = optparse.OptionParser()
	parser.add_option('-e', '--encode', dest='encode', help='encode')
	parser.add_option('-d', '--decode', dest='decode', help='decode')
	parser.add_option('-v', '--value', dest='value', help='value')
	(options,args) = parser.parse_args()
	if (options.encode == None) and (options.decode == None):
		print("""python3 code.py -e (加密) or -d (解密) and -v (加解密值)
		\n加密: 
		\n SHA序列: sha1 , sha2 , sha224 , sha256 , sha384 , sha512 , sha512-256 , sha3-224 , sha3-256 , sha3-384 , sha3-512 
		\n MD序列: md4 , md5  
		\n highwayhash序列: highwayhash256 , highwayhash64 , highwayhash128 
		\n blake序列: blake2b , blake2s 
		\n shake序列: shake-128 , shake-256  
		\n 其它: base64 , aes-128-cbc , des-cbc , hmac , url
		\n解密:
		\n SHA序列(纯数值碰撞): sha1 , sha224 , sha256 , sha384 , sha512
		\n MD序列(纯数值碰撞): md4 , md5
		\n 其它: base64 , aes-128-cbc , des-cbc , url
		""")
		return
	if (options.decode != None) and (options.value != None):
		decode = str(options.decode)
		value = str(options.value)
		value = decodes(decode,value)
		print('解密信息: {}'.format(value))
	elif ((options.encode != None) and (options.value != None)) or \
		(((options.encode == 'HighwayHash256') or (options.encode == 'highwayhash256')) or ((options.encode == 'Highway256') or (options.encode == 'highway256'))):
		encode = str(options.encode)
		value = str(options.value)
		print("离线，在线均支持的: sha1 , sha384 , md4 , md5 , sha256 , sha512 , sha3-512 , sha3-384\n")
		local_encode = """blake2b , blake2s , shake-256 , shake-128 , sha3-224 , base64 , sha224，aes-128-cbc , des-cbc , hmac , url"""
		api_encode = """highwayhash256 , highwayhash64 , highwayhash128 , sha512-256 , sha3-256 , sha2"""
		interface = input('仅离线: ' + local_encode + '\n' + '仅在线: ' + api_encode + '\n' + '\033[0;31;40m 在线1' + '离线2' + '全局匹配3：\033[0m')
		try:
			interface = int(interface)
		except ValueError:
			interface = 3
		if(interface == 1):
			encode = api(encode,value)
			if (encode != 'NO'):
				print('加密成功:' + str(encode))
		elif(interface == 2):
			local_status = encodes(encode, value)
			if(local_status != 'NO'):
				print('加密成功:' + str(local_status))
			else:
				print('不支持此加密方式')
		elif(interface == 3):
			local_status = encodes(encode,value)
			if(local_status != 'NO'):
				print('加密成功:' + str(local_status))
			elif(local_status == 'NO'):
				netstatus = status()
				if(netstatus == 'OK'):
					encode = api(encode,value)
					if(encode != 'NO'):
						print('加密成功:' + str(encode))
					else:
						print('不支持此加密方式')

if __name__ == '__main__':
	main()
