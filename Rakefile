require 'rubygems'
gem 'echoe'
require 'echoe'

Echoe.new('tem_openssl') do |p|
  p.project = 'tem' # rubyforge project
  
  p.author = 'Victor Costan'
  p.email = 'victor@costan.us'
  p.summary = 'TEM (Trusted Execution Module) engine for OpenSSL.'
  p.url = 'http://tem.rubyforge.org'
  p.dependencies = ['tem_ruby >=0.10.2']
  
  p.need_tar_gz = !Platform.windows?
  p.need_zip = !Platform.windows?
  p.rdoc_pattern = /^(lib|bin|tasks|ext)|^BUILD|^README|^CHANGELOG|^TODO|^LICENSE|^COPYING$/  
end

if $0 == __FILE__
  Rake.application = Rake::Application.new
  Rake.application.run
end
