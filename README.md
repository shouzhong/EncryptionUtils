# EncryptionUtils
## 说明
加密工具类，这里收集了一些常用的加密方法，包括AES，DES，3DES，MD5，RSA，SHA1，SHA256，SHA384，SHA512。
## 使用
### 依赖（审核中）
```
compile 'com.wuyifeng:EncryptionUtils:1.0.0'
```
### 使用说明
以下所有方法都为静态方法。
#### AESUtils
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | AES加密后转为Base64编码</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return Base64密文
String encrypt2HexString(final byte[] data, final byte[] key) | AES加密后转为16进制</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return 16进制密文
byte[] encrypt(final byte[] data, final byte[] key | AES加密</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return 密文
byte[] decryptBase64(final byte[] data, final byte[] key) | AES解密Base64编码密文</br>@param data Base64编码密文</br>@param key  16、24、32字节秘钥</br>@return 明文
byte[] decryptHexString(final String data, final byte[] key) | AES解密16进制密文</br>@param data 16进制密文</br>@param key  16、24、32字节秘钥</br>@return 明文
byte[] decrypt(final byte[] data, final byte[] key) | AES解密</br>@param data 密文</br>@param key  16、24、32字节秘钥</br>@return 明文
#### DES3Utils
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | 3DES加密后转为Base64编码</br>@param data 明文</br>@param key  24字节秘钥</br>@return Base64密文
String encrypt2HexString(final byte[] data, final byte[] key) | 3DES加密后转为16进制</br>@param data 明文</br>@param key  24字节秘钥</br>@return 16进制密文
byte[] encrypt(final byte[] data, final byte[] key) | 3DES加密</br>@param data 明文</br>@param key  24字节密钥</br>@return 密文
byte[] decryptBase64(final byte[] data, final byte[] key) | 3DES解密Base64编码密文</br>@param data Base64编码密文</br>@param key  24字节秘钥</br>@return 明文
byte[] decryptHexString(final String data, final byte[] key) | 3DES解密16进制密文</br>@param data 16进制密文</br>@param key  24字节秘钥</br>@return 明文
byte[] decrypt(final byte[] data, final byte[] key) | 3DES解密</br>@param data 密文</br>@param key  24字节密钥</br>@return 明文
#### DESUtils
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | DES加密后转为Base64编码</br>@param data 明文</br>@param key  8字节秘钥</br>@return Base64密文
String encrypt2HexString(final byte[] data, final byte[] key) | DES加密后转为16进制</br>@param data 明文</br>@param key  8字节秘钥</br>@return 16进制密文
byte[] encrypt(final byte[] data, final byte[] key) | DES加密</br>@param data 明文</br>@param key  8字节密钥</br>@return 密文
byte[] decryptBase64(final byte[] data, final byte[] key) | DES解密Base64编码密文</br>@param data Base64编码密文</br>@param key  8字节秘钥</br>@return 明文
byte[] decryptHexString(final String data, final byte[] key) | DES解密16进制密文</br>@param data 16进制密文</br>@param key  8字节秘钥</br>@return 明文
byte[] decrypt(final byte[] data, final byte[] key) | DES解密</br>@param data 密文</br>@param key  8字节密钥</br>@return 明文
#### MD5Utils
方法名 | 说明
------------ | -------------
String encrypt2String(final String data, final String salt) | MD5加密</br>@param data 明文字符串</br>@param salt 盐</br>@return 16进制加盐密文
String encrypt2String(final byte[] data) | MD5加密</br>@param data 明文字节数组</br>@return 16进制密文
String encrypt2String(final byte[] data, final byte[] salt) | MD5加密</br>@param data 明文字节数组</br>@param salt 盐字节数组</br>@return 16进制加盐密文
byte[] encrypt(final byte[] data) | MD5加密</br>@param data 明文字节数组</br>@return 密文字节数组
String encryptFile2String(final String filePath) | MD5加密文件</br>@param filePath 文件路径</br>@return 文件的16进制密文
byte[] encryptFile(final String filePath) | MD5加密文件</br>@param filePath 文件路径</br>@return 文件的MD5校验码
String encryptFile2String(final File file) | MD5加密文件</br>@param file 文件</br>@return 文件的16进制密文
byte[] encryptFile(final File file) | MD5加密文件</br>@param file 文件</br>@return 文件的MD5校验码
String encryptHmac2String(final String data, final String key) | HmacMD5加密</br>@param data 明文字符串</br>@param key 秘钥</br>@return 16进制密文
String encryptHmac2String(final byte[] data, final byte[] key) | HmacMD5加密</br>@param data 明文字节数组</br>@param key 秘钥</br>@return 16进制密文
byte[] encryptHmac(final byte[] data, final byte[] key) | HmacMD5加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 密文字节数组
#### RSAUtils
方法名 | 说明
------------ | -------------
密钥
KeyPair generateRSAKeyPair(int keyLength) | 随机生成RSA密钥对</br>@param keyLength 密钥长度，范围：512～2048 一般1024</br>@return 密钥对
PrivateKey getPrivateKey(String privateKey) | 获取私钥</br>@param privateKey 私钥字符串</br>@return 私钥
PrivateKey getPrivateKey(byte[] privateKey) | 获取私钥</br>@param privateKey 私钥数据</br>@return 私钥
PublicKey getPublicKey(String publicKey) | 获取公钥</br>@param publicKey 公钥字符串</br>@return 公钥
PublicKey getPublicKey(byte[] publicKey) | 获取公钥</br>@param publicKey 公钥数据</br>@return 公钥

#### SHA1Utils
#### SHA256Utils
#### SHA384Utils
#### SHA512Utils
