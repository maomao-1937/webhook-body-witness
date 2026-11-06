# webhook-body-witness

[![tests](https://github.com/maomao-1937/webhook-body-witness/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/webhook-body-witness/actions/workflows/tests.yml)

Compare two local body files against the same GitHub webhook signature. Use Python 3.11 or newer from the source directory.

```sh
python webhook_body_witness.py fixtures/demo-key.bin fixtures/signature.txt fixtures/captured.bin fixtures/candidate.bin
```

The synthetic example returns `{"captured_match":true,"candidate_match":false}`. Its candidate has one extra newline. The key file holds exact bytes, including any newline. The signature file contains a lowercase `sha256=` value with 64 lowercase hexadecimal digits and an optional final LF or CRLF. Each body is read as bytes without JSON decoding.

Exit 0 means the captured file matches. Exit 1 means the captured file differs. Exit 2 indicates invalid input or I/O failure. The second result is reported independently. The program outputs only match flags or a fixed invalid status. Keep real captures and key files outside the repository.

The key limit is 4,096 bytes and the key must be nonempty. The signature limit is 73 bytes. Either body may be empty or up to 1 MiB. The tool checks all path spellings before reading files. Use trusted local storage since symlinks and mounts can refer elsewhere. HMAC comparison covers the supplied bytes and key. Event handling and replay policies belong to the receiver.

## 中文

上面的命令比较两份本地文件能否匹配同一个 GitHub webhook 签名。示例使用公开测试数据，候选文件比捕获文件多一个换行。密钥文件和请求正文均按原始字节读取。签名文件可带一个末尾换行。真实密钥和请求捕获请放在仓库外。

退出码 0 表示捕获文件匹配，1 表示不匹配，2 表示输入或读写出错。JSON 单独给出候选文件是否匹配，省略路径、正文和密钥。每份正文最多 1 MiB，密钥非空且最多 4,096 字节。
