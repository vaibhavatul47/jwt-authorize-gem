# JwtAuthorize

This gem provides a common library for JWT authorization against a list of custom permissions.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "jwt_authorize", git: 'git@github.com:adobe-platform/jwt-authorize-gem.git'
```

And then execute:

    $ bundle install

## Usage

```ruby
def authorized?
  JwtAuthorize.authorized?(public_key, permissions, "bearer yourjwthere", "org/repo")
end

def public_key
  OpenSSL::PKey::RSA.new ENV["YOUR_PUBLIC_KEY"]
end

def permissions
  "deploy,admin"
end
```

## Test
`make test` or `./ci-test.sh`

During tests, the `JwtHelper` will create a new key pair and pass into the `JwtDecoder` class.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/adobe-platform/jwt-authorize-gem.

