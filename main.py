import hashlib, time
import hmac

# based on https://cloud.tencent.com/document/api/213/30654


def HMAC_SHA256(key, data):
    """请注意，不同的编程语言，HMAC 库函数中参数顺序可能不一样，请以实际情况为准。
    此处的伪代码密钥参数 key 在前，消息参数 data 在后。
    通常标准库函数会提供二进制格式的返回值，也可能会提供打印友好的十六进制格式的返回值，此处使用的是二进制格式。"""
    print(type(key), type(data))
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()


body = '{}'
SecretId = '1'
SecretKey = "1"


# 1. 拼接规范请求串
HTTPRequestMethod = 'POST'
CanonicalURI = '/'
CanonicalQueryString = ''
CanonicalHeaders = 'content-type:application/json\n' \
                   'host:ocr.tencentcloudapi.com\n'
SignedHeaders = 'content-type;host'
HashedRequestPayload = hashlib.sha256(str(body).encode('utf-8')).hexdigest()

CanonicalRequest = HTTPRequestMethod + '\n' + CanonicalURI + '\n' + CanonicalQueryString + '\n' + CanonicalHeaders + '\n' + SignedHeaders + '\n' + HashedRequestPayload


# 2. 拼接待签名字符串
Algorithm = 'TC3-HMAC-SHA256'
RequestTimestamp = 1635216626  # int(time.time())
Date = time.strftime("%Y-%m-%d", time.gmtime())
Service = 'ocr'
CredentialScope = f'{Date}/{Service}/tc3_request'
HashedCanonicalRequest = hashlib.sha256(str(CanonicalRequest).encode('utf-8')).hexdigest()

StringToSign = Algorithm + '\n' + str(RequestTimestamp) + '\n' + CredentialScope + '\n' + HashedCanonicalRequest


# 3. 计算签名
SecretDate = HMAC_SHA256(("TC3" + SecretKey).encode('utf-8'), Date.encode('utf-8'))
SecretService = HMAC_SHA256(SecretDate, Service.encode('utf-8'))
SecretSigning = HMAC_SHA256(SecretService, b"tc3_request")

Signature = HMAC_SHA256(SecretSigning, StringToSign.encode('utf-8')).hex()


# 4. 拼接 Authorization
Authorization = Algorithm + ' ' + 'Credential=' + SecretId + '/' + CredentialScope + ', ' + 'SignedHeaders=' + SignedHeaders + ', ' + 'Signature=' + Signature

print(Authorization)
