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
#### MD5Utils
#### RSAUtils
#### SHA1Utils
#### SHA256Utils
#### SHA384Utils
#### SHA512Utils
