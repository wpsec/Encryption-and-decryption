# 基于python的一款 加解密工具

加密:   SHA序列: sha1 , sha2 , sha224 , sha256 , sha384 , sha512 , sha512-256 , sha3-224 , sha3-256 , sha3-384 , sha3-512   MD序列: md4 , md5   highwayhash序列: highwayhash256 , highwayhash64 , highwayhash128   blake序列: blake2b , blake2s   shake序列: shake-128 , shake-256   其它: base64 , aes-128-cbc , des-cbc , hmac , url  

解密:   SHA序列(纯数值碰撞): sha1 , sha224 , sha256 , sha384 , sha512   MD序列(纯数值碰撞): md4 , md5   其它: base64 , aes-128-cbc , des-cbc , url





| 列表 | 离线解密 | 在线加密| 离线加密 |
| :--------: | :--------: | :----------: | :----------: |
| SHA1     |    √    |    √      |     √      |
| SHA2     |    x      |    √      |     x      |
| SHA224  |   √       |      x      |     √       |
| SHA256  |    √      |    √      |     √      |
| SHA384  |   √       |      √      |     √        |
| SHA512  |   √       |      √      |      √       |
| SHA512-256 | x | √| x|
|SHA3-224| x| x| √|
|SHA3-256| x| √| x|
|SHA3-384| x| √| √|
|SHA3-512| x| √| √|
|MD4| √| √| √|
|MD5| √| √| √|
|HighwayHash64| x| √|x|
|HighwayHash128| x| √|x|
|HighwayHash256| x| √|x|
|BASE64|√|x|√|
|AES-CBC|√|x|√|
|DES-CBC|√|x|√|
|HMAC|x|x|√|
|URL|√|x|√|





# 使用方法
![image](https://github.com/wpsec/Encryption-and-decryption/blob/main/jpeg/Image.png)
