use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;

use t::Util;

my $app = t::Util->create_app();

test_psgi $app => sub {
    my $cb = shift;

    subtest 'passthrogth' => sub {
        is $cb->(GET '/')->content,              'GET /';
        is $cb->(POST '/')->content,             'POST /';
        is $cb->(GET '/path/to/hoge')->content,  'GET /path/to/hoge';
        is $cb->(POST '/path/to/hoge')->content, 'POST /path/to/hoge';
    };

    subtest 'method not allowed' => sub {
        is $cb->(GET '/openid/authorize')->code, 405;
        is $cb->(POST '/openid/callback')->code, 405;
    };
};

done_testing;
