#!/bin/bash

bundle install && bundle exec rubocop && bundle exec rake spec