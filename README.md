# Netpayclient for ruby

银联商户会员 ruby

## 依赖
* mcrypt (用于[ruby-mcrypt](https://github.com/kingpong/ruby-mcrypt))
```
# 安装mcrypt (ubuntu)
sudo apt-get install mcrypt libmcrypt-dev
```

## API

### Netpayclient.build_key(path: nil, hash: {})
```ruby
Netpayclient.build_key(path: 'path/to/MerPrK.key')
# or
Netpayclient.build_key(hash: {
  MERID: '8435...4395',
  prikeyS: '4234...423',
  prikeyE: '472...48324',
})
```

### Netpayclient.sign(msg)

### Netpayclient.sign_order(merid, ordno, amount, curyid, transdate, transtype)

### Netpayclient.verify(plain, checkvalue)

### Netpayclient.verify_trans_response(merid, ordno, amount, curyid, transdate, transtype, ordstatus, check)
