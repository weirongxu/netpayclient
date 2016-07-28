require "netpayclient/version"

module Netpayclient
  require 'openssl'

  DES_KEY = 'SCUBEPGW'
  HASH_PAD = '0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a05000414'

  module Crypto
    require 'mcrypt'
    def self.crypto
      if defined?(@@crypto).nil?
        @@crypto = Mcrypt.new(:des, :cbc)
        @@crypto.key = DES_KEY
        @@crypto.iv = "\x00" * 8
        @@crypto.padding = false
      end
      @@crypto
    end

    def self.decrypt(str)
      if str.blank?
        "\xEE\xB3\x16\x86\xAB\x84G\x90"
      else
        self.crypto.decrypt(str)
      end
    end
  end

  def self.build_key(path: nil, hash: {})
    Netpayclient.new(path: path, hash: hash)
  end

  class Netpayclient
    class << self
      def hex2bin(hexdata)
        [hexdata].pack "H*"
      end

      def padstr(src, len=256, chr='0', d='L')
        src.strip!
        case d
        when 'L'
          src.rjust(len, chr)
        else
          src.ljust(len, chr)
        end
      end

      def bin2int(bindata)
        bchexdec(bindata.unpack('H*')[0])
      end

      def bchexdec(hexdata)
        hexdata.to_i(16)
      end

      def bcdechex(decdata)
        decdata.to_s(16)
      end

      def sha1_128(string)
        require 'digest/sha1'
        hash = Digest::SHA1.hexdigest(string)
        sha_bin = hex2bin(hash)
        sha_pad = hex2bin(HASH_PAD)
        sha_pad + sha_bin
      end

      def mybcpowmod(num, pow, mod)
        num.to_bn.mod_exp(pow, mod)
      end

      def rsa_encrypt(private_key, input)
        p = bin2int(private_key[:prime1])
        q = bin2int(private_key[:prime2])
        u = bin2int(private_key[:coefficient])
        dP = bin2int(private_key[:prime_exponent1])
        dQ = bin2int(private_key[:prime_exponent2])
        c = bin2int(input)
        cp = c % p
        cq = c % q
        a = mybcpowmod(cp, dP, p)
        b = mybcpowmod(cq, dQ, q)
        if a > b
          result = a - b
        else
          result = b - a
          result = p - result
        end
        result = result % p
        result = result * u
        result = result % p
        result = result * q
        result = result + b
        ret = bcdechex(result)
        ret = padstr(ret).upcase
        ret.size == 256 ? ret : false
      end
    end

    def initialize(path: nil, hash: {})
      require 'iniparse'
      @private_key = {}
      if path
        config_hash = IniParse.parse(File.read(path))['NetPayClient']
      else
        config_hash = hash
      end
      hex = ""
      if not config_hash['MERID'].nil?
        ret = config_hash['MERID']
        @private_key[:MERID] = ret
        hex = config_hash['prikeyS'][80...config_hash['prikeyS'].size]
      elsif not config_hash['PGID'].nil?
        ret = config_hash['PGID']
        @private_key[:PGID] = ret
        hex = config_hash['pubkeyS'][48...config_hash['pubkeyS'].size]
      else
        raise 'config error'
      end
      bin = self.class.hex2bin(hex)
      @private_key[:modulus] = bin[0,128]

      prime1 = bin[384,64]
      enc = Crypto.decrypt(prime1)
      @private_key[:prime1] = enc
      prime2 = bin[448,64]
      enc = Crypto.decrypt(prime2)
      @private_key[:prime2] = enc
      prime_exponent1 = bin[512,64]
      enc = Crypto.decrypt(prime_exponent1)
      @private_key[:prime_exponent1] = enc
      prime_exponent2 = bin[576,64]
      enc = Crypto.decrypt(prime_exponent2)
      @private_key[:prime_exponent2] = enc
      coefficient = bin[640,64]
      enc = Crypto.decrypt(coefficient)
      @private_key[:coefficient] = enc
    end

    def rsa_decrypt(input)
      check = self.class.bchexdec(input)
      modulus = self.class.bin2int(@private_key[:modulus])
      exponent = self.class.bchexdec("010001")
      result = self.class.mybcpowmod(check, exponent, modulus)
      rb = self.class.bcdechex(result)
      self.class.padstr(rb).upcase
    end

    def sign(msg)
      if not @private_key.key?(:MERID)
        return false
      end
      hb = self.class.sha1_128(msg)
      return self.class.rsa_encrypt(@private_key, hb)
    end

    def sign_order(merid, ordno, amount, curyid, transdate, transtype)
      return false if (merid.size!=15)
      return false if (ordno.size!=16)
      return false if (amount.size!=12)
      return false if (curyid.size!=3)
      return false if (transdate.size!=8)
      return false if (transtype.size!=4)
      plain = merid + ordno + amount + curyid + transdate + transtype
      return sign(plain)
    end

    def verify(plain, check)
      return false if not @private_key.key?(:PGID)
      return false if check.size != 256
      hb = self.class.sha1_128(plain)
      hbhex = hb.unpack('H*')[0].upcase
      rbhex = rsa_decrypt(check)
      return hbhex == rbhex ? true : false
    end

    def verify_trans_response(merid, ordno, amount, curyid, transdate, transtype, ordstatus, check)
      return false if (merid.size!=15)
      return false if (ordno.size!=16)
      return false if (amount.size!=12)
      return false if (curyid.size!=3)
      return false if (transdate.size!=8)
      return false if (transtype.size!=4)
      return false if (ordstatus.size!=4)
      return false if (check.size!=256)
      plain = merid + ordno + amount + curyid + transdate + transtype + ordstatus
      return verify(plain, check)
    end
  end
end
