use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;

use t::Util;

my $app = t::Util->create_app();

local our $HANDLER;

no warnings qw/redefine/;
local *Plack::Middleware::Auth::OpenID::handle_authenticate = sub { $HANDLER = 'authenticate'; [200, [], ['OK']] };
local *Plack::Middleware::Auth::OpenID::handle_callback  = sub { $HANDLER = 'callback';  [200, [], ['OK']] };
use warnings qw/redefine/;

subtest 'default' => sub {
    my $app = t::Util->create_app();

    test_psgi $app => sub {
        my $cb = shift;

        subtest 'passthrough' => sub {
            local $HANDLER;
            $cb->(GET '/');
            is $HANDLER, undef;
        };

        subtest 'authenticate' => sub {
            local $HANDLER;
            $cb->(GET '/openid/authenticate');
            is $HANDLER, 'authenticate';
        };

        subtest 'callback' => sub {
            local $HANDLER;
            $cb->(GET '/openid/callback');
            is $HANDLER, 'callback';
        };
    };
};

subtest 'customize' => sub {
    my $app = t::Util->create_app(
        authenticate_path => '/test/openid/authenticate',
        callback_path  => '/test/openid/callback',
    );

    test_psgi $app => sub {
        my $cb = shift;

        subtest 'passthrough' => sub {
            local $HANDLER;
            $cb->(GET '/openid/authenticate');
            is $HANDLER, undef;
            $cb->(GET '/openid/callback');
            is $HANDLER, undef;
        };

        subtest 'authenticate' => sub {
            local $HANDLER;
            $cb->(GET '/test/openid/authenticate');
            is $HANDLER, 'authenticate';
        };

        subtest 'callback' => sub {
            local $HANDLER;
            $cb->(GET '/test/openid/callback');
            is $HANDLER, 'callback';
        };
    };
};


subtest 'callback passthrough' => sub {
    my $app = t::Util->create_app();

    no warnings qw/redefine/;
    local *Plack::Middleware::Auth::OpenID::handle_callback  = sub { undef };
    use warnings qw/redefine/;

    test_psgi $app => sub {
        my $cb = shift;
        is $cb->(GET '/openid/callback')->content, 'GET /openid/callback';
    };
};

done_testing;
