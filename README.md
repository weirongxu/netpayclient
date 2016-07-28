# Netpayclient for ruby

银联商户会员 ruby

## 依赖
* mcrypt (用于[ruby-mcrypt](https://github.com/kingpong/ruby-mcrypt))
```
# 安装mcrypt (ubuntu)
sudo apt-get install mcrypt libmcrypt-dev
```

## 使用 & API

### Netpayclient.build_key(path: nil, hash: {})
```ruby
netpay = Netpayclient.build_key(path: 'path/to/MerPrK.key')
# or
netpay = Netpayclient.build_key(hash: {
  MERID: '8435...4395',
  prikeyS: '4234...423',
  prikeyE: '472...48324',
})
```

### 签名 sign
```ruby
# netpay = Netpayclient.build_key(...)
netpay.sign('834...645')
```

### 订单签名 sign_order
```ruby
netpay.sign_order(merid, ordno, amount, curyid, transdate, transtype)
```

### 应答数据的签名验证 verify
```ruby
netpay.verify(plain, checkvalue)
```

### 应答数据的签名包装 verify_trans_response
```ruby
netpay.verify_trans_response(merid, ordno, amount, curyid, transdate, transtype, ordstatus, check)
```
