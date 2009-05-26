require 'pp'

# :nodoc: namespace
module Tem::OpenSSL

class Key
  include TemTools
  
  attr_reader :pub_key
  
  def initialize(pub_key, priv_decrypt_sec, priv_encrypt_sec, priv_sign_sec)
    @pub_key = pub_key
    @priv_decrypt_sec = priv_decrypt_sec
    @priv_encrypt_sec = priv_encrypt_sec
    @priv_sign_sec = priv_sign_sec
  end
  
  def to_tkfile
    @pub_key.ssl_key.to_s + [@priv_decrypt_sec.to_array,
                             @priv_encrypt_sec.to_array,
                             @priv_sign_sec.to_array].to_yaml
  end
  
  def privk_decrypt(data, tem)
    TemTools.crypt_with_sec data, @priv_decrypt_sec, tem
  end

  def privk_encrypt(data, tem)
    TemTools.crypt_with_sec data, @priv_encrypt_sec, tem
  end
  
  def privk_sign(data, tem)
    TemTools.sign_with_sec data, @priv_sign_sec, tem
  end
  
  def self.new_tem_key(tem)
    keys = TemTools.generate_key_on_tem tem
    decrypt_sec = TemTools.crypting_sec keys[:privk], tem, :decrypt
    encrypt_sec = TemTools.crypting_sec keys[:privk], tem, :encrypt
    sign_sec = TemTools.signing_sec keys[:privk], tem
    self.new keys[:pubk], decrypt_sec, encrypt_sec, sign_sec
  end
  
  def self.load_from_tkfile(file)
    ossl_pub_key = OpenSSL::PKey::RSA.new file
    pub_key = Tem::Key.new_from_ssl_key ossl_pub_key
    begin
      ds_ary, es_ary, ss_ary = *YAML.load(file)
      priv_decrypt_sec = Tem::SecPack.new_from_array ds_ary
      priv_encrypt_sec = Tem::SecPack.new_from_array es_ary      
      priv_sign_sec = Tem::SecPack.new_from_array ss_ary
    rescue
      priv_decrypt_sec = nil
      priv_encrypt_sec = nil
      priv_sign_sec = nil
    end
    self.new pub_key, priv_decrypt_sec, priv_encrypt_sec, priv_sign_sec
  end  
end

end  # namespace Tem::OpenSSL
