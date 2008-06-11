require 'tem_openssl'
require 'test/unit'

class ExecutorTest < Test::Unit::TestCase
  def setup
    Tem::OpenSSL::Executor.run ['reset']

    # generate key and extract public key
    Tem::OpenSSL::Executor.run ['rsagen', '2048', '-out', 'test_key.tkey']    
    Tem::OpenSSL::Executor.run ['rsa', '-in', 'test_key.tkey', '-out', 'test_key.pem', '-pubout'], :no_tem => true    
  end
  
  def teardown
    ['test_key.tkey', 'test_key.pem'].each { |fname| File.delete fname }
  end

  def test_encryption    
    # test encryption and decryption (using the PEM file for the public key)
    plain_text = 'Simple encryption test.\n'
    File.open('test_plain.txt', 'wb') { |f| f.write plain_text }
    Tem::OpenSSL::Executor.run ['rsautl', '-encrypt', '-inkey', 'test_key.pem', '-in', 'test_plain.txt', '-pkcs', '-out', 'test_enc.txt'], :no_tem => true
    Tem::OpenSSL::Executor.run ['rsautl', '-decrypt', '-inkey', 'test_key.tkey', '-in', 'test_enc.txt', '-pkcs', '-out', 'test_plain2.txt']
    assert_equal plain_text, File.open('test_plain2.txt', 'rb') { |f| f.read }, 'data corruption in encryption/decryption'    
    ['test_plain.txt', 'test_plain2.txt', 'test_enc.txt'].each { |fname| File.delete fname }
    
    # test encryption and decryption (using the TEM-bound file for the public key)
    plain_text = 'Simple encryption test.\n'
    File.open('test_plain.txt', 'wb') { |f| f.write plain_text }
    Tem::OpenSSL::Executor.run ['rsautl', '-encrypt', '-inkey', 'test_key.tkey', '-in', 'test_plain.txt', '-pkcs', '-out', 'test_enc.txt']
    Tem::OpenSSL::Executor.run ['rsautl', '-decrypt', '-inkey', 'test_key.tkey', '-in', 'test_enc.txt', '-pkcs', '-out', 'test_plain2.txt']
    assert_equal plain_text, File.open('test_plain2.txt', 'rb') { |f| f.read }, 'data corruption in encryption/decryption'    
    ['test_plain.txt', 'test_plain2.txt', 'test_enc.txt'].each { |fname| File.delete fname }     
  end
  
  def test_fake_signing
    # test fake (openssl-compatible) signing
    plain_text = 'Simple fake-signing test.\n'
    File.open('test_plain.txt', 'wb') { |f| f.write plain_text }
    Tem::OpenSSL::Executor.run ['rsautl', '-sign', '-inkey', 'test_key.tkey', '-in', 'test_plain.txt', '-pkcs', '-out', 'test_fsign.txt']
    Tem::OpenSSL::Executor.run ['rsautl', '-verify', '-inkey', 'test_key.pem', '-in', 'test_fsign.txt', '-pkcs', '-out', 'test_fverify.txt']
    assert_equal plain_text, File.open('test_fverify.txt', 'rb') { |f| f.read }, 'data corruption in fake-sign/verification'    
    ['test_plain.txt', 'test_fsign.txt', 'test_fverify.txt'].each { |fname| File.delete fname }     
  end
  
  def test_xsigning
    # test proper signing (using the PEM file for the public key)
    plain_text = 'Simple signing test.\n'
    File.open('test_plain.txt', 'wb') { |f| f.write plain_text }
    Tem::OpenSSL::Executor.run ['rsautl', '-xsign', '-inkey', 'test_key.tkey', '-in', 'test_plain.txt', '-pkcs', '-out', 'test_sign.txt']
    Tem::OpenSSL::Executor.run ['rsautl', '-xverify', '-inkey', 'test_key.pem', '-in', 'test_sign.txt', '-indata', 'test_plain.txt', '-pkcs', '-out', 'test_verify.txt'], :no_tem => true
    assert_equal "true", File.open('test_verify.txt', 'rb') { |f| f.read }, 'data corruption in sign/verification'
    ['test_plain.txt', 'test_sign.txt', 'test_verify.txt'].each { |fname| File.delete fname }     
  end
end
