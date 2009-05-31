# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{tem_openssl}
  s.version = "0.3.6"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = ["Victor Costan"]
  s.date = %q{2009-05-31}
  s.default_executable = %q{openssl_tem}
  s.description = %q{TEM (Trusted Execution Module) engine for OpenSSL.}
  s.email = %q{victor@costan.us}
  s.executables = ["openssl_tem"]
  s.extra_rdoc_files = ["bin/openssl_tem", "CHANGELOG", "lib/openssl/executor.rb", "lib/openssl/key.rb", "lib/openssl/tem_tools.rb", "lib/tem_openssl.rb", "LICENSE", "README"]
  s.files = ["bin/openssl_tem", "CHANGELOG", "lib/openssl/executor.rb", "lib/openssl/key.rb", "lib/openssl/tem_tools.rb", "lib/tem_openssl.rb", "LICENSE", "Manifest", "Rakefile", "README", "test/test_executor.rb", "tem_openssl.gemspec"]
  s.homepage = %q{http://tem.rubyforge.org}
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Tem_openssl", "--main", "README"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{tem}
  s.rubygems_version = %q{1.3.3}
  s.summary = %q{TEM (Trusted Execution Module) engine for OpenSSL.}
  s.test_files = ["test/test_executor.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<tem_ruby>, [">= 0.10.2"])
    else
      s.add_dependency(%q<tem_ruby>, [">= 0.10.2"])
    end
  else
    s.add_dependency(%q<tem_ruby>, [">= 0.10.2"])
  end
end
