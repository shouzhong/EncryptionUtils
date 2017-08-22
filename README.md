# EncryptionUtils
## 说明
加密工具类，这里收集了一些常用的加密方法，包括AES，DES，3DES，MD5，RSA，SHA1，SHA256，SHA384，SHA512。
## 使用
### 依赖（审核中）
```
compile 'com.wuyifeng:EncryptionUtils:1.0.0'
```
### 使用说明
#### AESUtils
##### encrypt2Base64
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | AES加密后转为Base64编码</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return Base64密文
第一列内容 | 第二列内容
#### DES3Utils
#### DESUtils
#### MD5Utils
#### RSAUtils
#### SHA1Utils
#### SHA256Utils
#### SHA384Utils
#### SHA512Utils
