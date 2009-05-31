# :nodoc: namespace
module Tem::OpenSSL
  
module TemTools
  # Generate an RSA key pair on the TEM.
  #
  # Runs slower than OpenSSL-based generation, but uses a hardware RNG.
  def self.generate_key_on_tem(tem)
    kdata = tem.tk_gen_key :asymmetric
    pubk = tem.tk_read_key kdata[:pubk_id], kdata[:authz]
    tem.tk_delete_key kdata[:pubk_id], kdata[:authz]
    privk = tem.tk_read_key kdata[:privk_id], kdata[:authz]
    tem.tk_delete_key kdata[:privk_id], kdata[:authz]
    
    return {:privk => privk, :pubk => pubk}
  end
  
  # Generates a SECpack that encrypts/decrypts a user-supplied blob.
  #
  # The SECpack is tied down to a TEM.
  def self.crypting_sec(key, tem, mode = :decrypt)
    crypt_sec = tem.assemble do |s|
      # load the key in the TEM
      s.ldwc :const => :key_data
      s.rdk
      # allocate the output buffer
      s.ldwc :const => 512
      s.outnew
      # decrypt the given data
      s.ldw :from => :input_length
      s.ldwc :const => :input_data
      s.ldwc :const => -1
      s.send({:encrypt => :kevb, :decrypt => :kdvb}[mode])
      s.halt
      
      # key material
      s.label :key_data
      s.data :tem_ubyte, key.to_tem_key
      
      # user-supplied argument: the length of the blob to be encrypted/decrypted
      s.label :input_length
      s.data :tem_ushort, 256
      
      # user-supplied argument: the blob to be encrypted/decrypted
      s.label :input_data
      s.zeros :tem_ubyte, 512
      
      s.label :sec_stack
      s.stack 4
    end
    crypt_sec.bind tem.pubek, :key_data, :input_length
    crypt_sec
  end
  
  # Generates a SECpack that decrypts a user-supplied blob.
  #
  # The SECpack is tied down to a TEM.
  def self.signing_sec(key, tem)
    sign_sec = tem.assemble do |s|
      # load the key in the TEM
      s.ldwc :const => :key_data
      s.rdk
      # allocate the output buffer
      s.ldwc :const => key.ssl_key.n.num_bytes + 1
      s.outnew
      # sign the given data
      s.ldw :from => :input_length
      s.ldwc :const => :input_data
      s.ldwc :const => -1
      s.ksvb
      s.halt
      
      # key material
      s.label :key_data
      s.data :tem_ubyte, key.to_tem_key
      
      # user-supplied argument: the length of the blob to be signed
      s.label :input_length
      s.data :tem_ushort, 256
      
      # user-supplied argument: the blob to be signed
      s.label :input_data
      s.zeros :tem_ubyte, 512
      
      s.label :sec_stack
      s.stack 4
    end
    sign_sec.bind tem.pubek, :key_data, :input_length
    sign_sec
  end
  
  
  # Encrypts/decrypts using a SECpack generated via a previous call to
  # crypting_sec.
  def self.crypt_with_sec(encrypted_data, dec_sec, tem)
    # convert the data string to an array of numbers
    ed = encrypted_data.unpack 'C*'
    
    # patch the data and its length into the SEC 
    elen = tem.to_tem_ushort ed.length
    dec_sec.body[dec_sec.label_address(:input_length), elen.length] = elen
    dec_sec.body[dec_sec.label_address(:input_data), ed.length] = ed
    
    # run the sec and convert its output to a string
    dd = tem.execute dec_sec
    decrypted_data = dd.pack 'C*'
    
    return decrypted_data
  end
  
  # Signs using a SECpack generated via a previous call to signing_sec.
  def self.sign_with_sec(data, sign_sec, tem)
    # convert the data string to an array of numbers
    d = data.unpack 'C*'
    
    # patch the data and its length into the SEC 
    len = tem.to_tem_ushort d.length
    sign_sec.body[sign_sec.label_address(:input_length), len.length] = len
    sign_sec.body[sign_sec.label_address(:input_data), d.length] = d
    
    # run the sec and convert its output to a string
    s = tem.execute sign_sec
    signature = s.pack 'C*'
    
    return signature
  end  
end

end  # namespace Tem::OpenSSL
