default: test

deps:
	bundle install

test: deps
	bundle exec rubocop
	bundle exec rspec

