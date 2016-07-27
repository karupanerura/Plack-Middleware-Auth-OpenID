use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use Plack::Request;
use Plack::Middleware::Auth::OpenID;
use LWPx::ParanoidHandler;
use Scalar::Util qw/refaddr/;

use t::Util;

sub abstract_sub { die 'no reach here' }

subtest 'prepare_app' => sub {
    subtest 'check required parameter' => sub {
        my %param = (
            origin      => 'http://localhost/',
            on_verified => \&abstract_sub,
            on_error    => \&abstract_sub
        );

        my %args;
        for my $key (qw/origin on_verified on_error/) {
            eval { Plack::Middleware::Auth::OpenID->new(%args)->prepare_app };
            like $@, qr!^no required parameter: $key\b!, "$key is required"
                or diag "$@";
            $args{$key} = $param{$key};
        }

        eval { Plack::Middleware::Auth::OpenID->new(%args)->prepare_app };
        is $@, '', 'all required parameter is specified';
    };

    subtest 'set default' => sub {
        my $middleware = Plack::Middleware::Auth::OpenID->new(origin => 'http://localhost/', on_verified => \&abstract_sub, on_error => \&abstract_sub);
        $middleware->prepare_app;
        for my $param (qw/openid_param authenticate_path callback_path callback_path/) {
            ok defined $middleware->$param, "param: $param";
        }
    };

    subtest 'no override specified value' => sub {
        for my $param (qw/openid_param authenticate_path callback_path callback_path/) {
            my $value = "value:$param";
            my $middleware = Plack::Middleware::Auth::OpenID->new(origin => 'http://localhost/', on_verified => \&abstract_sub, on_error => \&abstract_sub, $param => $value);
            $middleware->prepare_app;
            is $middleware->$param, $value, "param: $param";
        }
    };

    subtest 'inflate origin from string' => sub {
        my $middleware = Plack::Middleware::Auth::OpenID->new(origin => 'http://localhost/', on_verified => \&abstract_sub, on_error => \&abstract_sub);
        $middleware->prepare_app;
        isa_ok $middleware->origin, 'URI';
    };

    subtest 'no inflate origin from URI object' => sub {
        my $origin = URI->new('http://localhost/');
        my $middleware = Plack::Middleware::Auth::OpenID->new(origin => $origin, on_verified => \&abstract_sub, on_error => \&abstract_sub);
        $middleware->prepare_app;
        isa_ok $middleware->origin, 'URI';
        is refaddr($middleware->origin), refaddr($origin), 'same address';
    };
};

subtest '_make_csr' => sub {
    my $middleware = Plack::Middleware::Auth::OpenID->new(origin => 'http://localhost/', on_verified => \&abstract_sub, on_error => \&abstract_sub);
    $middleware->prepare_app;

    my $req = Plack::Request->new({ REQUEST_METHOD => 'GET' });
    my $csr = $middleware->_make_csr($req);
    isa_ok $csr, 'Net::OpenID::Consumer';

    subtest 'use LWPx::ParanoidHandler by default' => sub {
        my $called = 0;

        no warnings qw/redefine/;
        local *LWPx::ParanoidHandler::make_paranoid = sub { $called++ };
        use warnings qw/redefine/;

        my $csr = $middleware->_make_csr($req);
        is $called, 1;
    };

    subtest 'use LWPx::ParanoidAgent if specified' => sub {
        my $called = 0;

        no warnings qw/redefine/;
        local *LWPx::ParanoidHandler::make_paranoid = sub { $called++ };
        use warnings qw/redefine/;

        $middleware->ua(bless {}, 'LWPx::ParanoidAgent');
        my $csr = $middleware->_make_csr($req);
        is $called, 0;
    };
};

subtest 'callback_url' => sub {
    my $middleware = t::Util->create_middleware();
    $middleware->prepare_app();

    my $callback_url = $middleware->callback_url;
    isa_ok $callback_url, 'URI';
    is $callback_url->path_query, $middleware->callback_path, 'path_qeury is correct';
};

subtest 'end to end' => sub {
    my $app = t::Util->create_app();
    test_psgi $app => sub {
        my $cb = shift;

        subtest 'passthrogth' => sub {
            is $cb->(GET '/')->content,              'GET /', 'GET /';
            is $cb->(POST '/')->content,             'POST /', 'POST /';
            is $cb->(GET '/path/to/hoge')->content,  'GET /path/to/hoge', 'GET /path/to/hoge';
            is $cb->(POST '/path/to/hoge')->content, 'POST /path/to/hoge', 'POST /path/to/hoge';
        };

        subtest 'method not allowed' => sub {
            is $cb->(GET '/openid/authenticate')->code, 405, 'GET /openid/authenticate';
            is $cb->(POST '/openid/callback')->code, 405, 'POST /openid/callback';
        };
    };
};

done_testing;
