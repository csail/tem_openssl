# :nodoc: namespace
module Tem::OpenSSL
  
class Executor
  def initialize(args, test_options)
    @args = args
    # unknown args get thrown here
    @arg_bag = {}
    # read key from here
    @in_key = nil 
    # read (original) data from here
    @in_data = nil
    # read input from here
    @in = $stdin
    # dump output here
    @out = $stdout
    # run the procs here to clean up
    @cleanup_procs = []
    
    # hash of flags to help unit tests
    @test_options = test_options
    
    connect_to_tem
    parse_args
  end
    
  def run    
    case @args[0]
    when 'reset'
      @tem.kill
      @tem.activate
      @tem.emit
    when 'rsa'
      if @arg_bag[:pubout]
        @key = Tem::OpenSSL::Key.load_from_tkfile @in
        @out.write @key.pub_key.ssl_key.to_s
      end
    when 'rsagen'
      @key = Tem::OpenSSL::Key.new_tem_key @tem
      @out.write @key.to_tkfile
    when 'rsautl'
      @key = Tem::OpenSSL::Key.load_from_tkfile @in_key
      data = @in.read
      case
    when @arg_bag[:decrypt]
        # decrypting with private key
        result = @key.privk_decrypt data, @tem
      when @arg_bag[:encrypt]
        # encrypting with public key
        result = @key.pub_key.encrypt data
      when @arg_bag[:sign]
        # fake-signing (encrypting with private key)
        result = @key.privk_encrypt data, @tem
      when @arg_bag[:verify]
        # fake-verifying (decrypting with public key)
        result = @key.pub_key.decrypt data
      when @arg_bag[:xsign]
        result = @key.privk_sign data, @tem
      when @arg_bag[:xverify]
        orig_data = @in_data.read
        result = @key.pub_key.verify orig_data, data
      else
        # ?!
      end
      @out.write result
    end    
  end
  
  def parse_args
    0.upto(@args.length - 1) do |i|
      # the tokens that don't start with - are processed OOB
      next unless @args[i][0] == ?-
      case @args[i]
      when '-in'
        @in = File.open(@args[i + 1], 'rb')
        @cleanup_procs << Proc.new { @in.close }
      when '-inkey'
        @in_key = File.open(@args[i + 1], 'r')
        @cleanup_procs << Proc.new { @in_key.close }
      when '-indata'
        @in_data = File.open(@args[i + 1], 'r')
        @cleanup_procs << Proc.new { @in_data.close }
      when '-out'
        @out = File.open(@args[i + 1], 'wb')
        @cleanup_procs << Proc.new { @out.close }
      else
        @arg_bag[@args[i][1..-1].to_sym] = true
      end
    end
  end
  
  def cleanup
    @cleanup_procs.each { |p| p.call }
  end
  
  def connect_to_tem
    @tem = Tem.auto_tem
    if @tem    
      @cleanup_procs << Proc.new { @tem.disconnect; }
    end
  end
  
  def self.run(args, test_options = {})
    ex = self.new args, test_options
    ex.run
    ex.cleanup
  end
end

end  # namespace Tem::OpenSSL
