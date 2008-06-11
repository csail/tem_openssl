require 'pp'

class Tem::OpenSSL::Key
  include Tem::OpenSSL::TemTools
  
  attr_reader :pub_key
  
  def initialize(pub_key, priv_decrypt_sec, priv_encrypt_sec, priv_sign_sec)
    @pub_key = pub_key
    @priv_decrypt_sec = priv_decrypt_sec
    @priv_encrypt_sec = priv_encrypt_sec
    @priv_sign_sec = priv_sign_sec
  end
  
  def to_tkfile
    @pub_key.ssl_key.to_s + [@priv_decrypt_sec.to_array, @priv_encrypt_sec.to_array, @priv_sign_sec.to_array].to_yaml
  end
  
  def privk_decrypt(data, tem)
    Tem::OpenSSL::TemTools.crypt_with_sec(data, @priv_decrypt_sec, tem)
  end

  def privk_encrypt(data, tem)
    Tem::OpenSSL::TemTools.crypt_with_sec(data, @priv_encrypt_sec, tem)
  end
  
  def privk_sign(data, tem)
    Tem::OpenSSL::TemTools.sign_with_sec(data, @priv_sign_sec, tem)    
  end
  
  def self.new_tem_key(tem)
    keys = Tem::OpenSSL::TemTools.generate_key_on_tem(tem)
    priv_decrypt_sec = Tem::OpenSSL::TemTools.crypting_sec(keys[:privk], tem, :decrypt)
    priv_encrypt_sec = Tem::OpenSSL::TemTools.crypting_sec(keys[:privk], tem, :encrypt)
    priv_sign_sec = Tem::OpenSSL::TemTools.signing_sec(keys[:privk], tem)
    return self.new(keys[:pubk], priv_decrypt_sec, priv_encrypt_sec, priv_sign_sec)
  end
  
  def self.load_from_tkfile(f)
    ossl_pub_key = OpenSSL::PKey::RSA.new(f)
    pub_key = Tem::CryptoAbi::new_key_from_ssl(ossl_pub_key, true)
    begin
      ds_ary, es_ary, ss_ary = *YAML.load(f)
      priv_decrypt_sec = Tem::SecPack.new_from_array(ds_ary)
      priv_encrypt_sec = Tem::SecPack.new_from_array(es_ary)      
      priv_sign_sec = Tem::SecPack.new_from_array(ss_ary)
    rescue
      priv_decrypt_sec = nil
      priv_encrypt_sec = nil
      priv_sign_sec = nil
    end
    return self.new(pub_key, priv_decrypt_sec, priv_encrypt_sec, priv_sign_sec)
  end
  
end
