use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use URI;

use t::Util;

my $app = t::Util->create_app(cancel_path => '/canceled');

test_psgi $app => sub {
    my $cb = shift;

    subtest 'OpenID 2.0' => sub {
        t::Util->mock_for_open_id_v2();

        my $oic_time;

        subtest 'authenticate' => sub {
            my $res = $cb->(POST '/openid/authenticate', Content => [open_id => 'http://example.com/open_id']);
            is $res->code, 302 or diag $res->as_string;

            my $uri = URI->new($res->header('Location'));
            my %param = $uri->query_form;
            is $uri->scheme, 'http';
            is $uri->host,   'example.com';
            is $uri->path,   '/server';
            is $param{'openid.ns'},          'http://specs.openid.net/auth/2.0';
            is $param{'openid.mode'},        'checkid_immediate';
            like $param{'openid.return_to'}, qr!^\Qhttp://localhost/openid/callback?oic.time=\E[-a-zA-Z0-9]+$!;
            is $param{'openid.identity'},    'http://example.com/open_id';
            is $param{'openid.claimed_id'},  'http://example.com/open_id';
            is $param{'openid.realm'},       'http://localhost/';

            subtest 'no content' => sub {
                my $res = $cb->(POST '/openid/authenticate');
                is $res->code, 400 or diag $res->as_string;
                like $res->content, qr!^parameter open_id is required\b!;
            };

            subtest 'invalid open id' => sub {
                my $res = $cb->(POST '/openid/authenticate', Content => [open_id => 'http://example.com/invalid_open_id']);
                is $res->code, 400 or diag $res->as_string;
                like $res->content, qr!^not actually an openid\?  no_identity_server: Could not determine ID provider from URL\b!;
            };

            # XXX: prepare for next test
            ($oic_time) = $param{'openid.return_to'} =~ m!^\Qhttp://localhost/openid/callback?oic.time=\E([-a-zA-Z0-9]+)$!;
        };

        subtest 'callback' => sub {
            my $res = $cb->(GET "/openid/callback?oic.time=$oic_time&openid.assoc_handle=%7BHMAC-SHA1%7D%7B57956479%7D%7BVL%2BPMg%3D%3D%7D&openid.claimed_id=http%3A%2F%2Fexample.com%2Fopen_id&openid.identity=http%3A%2F%2Fexample.com%2Fopen_id&openid.mode=id_res&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.op_endpoint=http%3A%2F%2Fexample.com%2Fserver&openid.response_nonce=@{[ time ]}&openid.return_to=http%3A%2F%2Flocalhost%2Fopenid%2Fcallback%3Foic.time%3D${oic_time}&openid.sig=z90DnnLiziDzPa9doObwPCKcNLE%3D&openid.signed=assoc_handle%2Cclaimed_id%2Cidentity%2Cmode%2Cns%2Cop_endpoint%2Cresponse_nonce%2Creturn_to%2Csigned");
            is $res->code, 200 or diag $res->as_string;

            subtest 'invalid oic.time' => sub {
                my $res = $cb->(GET "/openid/callback?oic.time=1469415287-3c8b71160a5b71f40a0a&openid.assoc_handle=%7BHMAC-SHA1%7D%7B57956479%7D%7BVL%2BPMg%3D%3D%7D&openid.claimed_id=http%3A%2F%2Fexample.com%2Fopen_id&openid.identity=http%3A%2F%2Fexample.com%2Fopen_id&openid.mode=id_res&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.op_endpoint=http%3A%2F%2Fexample.com%2Fserver&openid.response_nonce=@{[ time ]}&openid.return_to=http%3A%2F%2Flocalhost%2Fopenid%2Fcallback%3Foic.time%3D${oic_time}&openid.sig=z90DnnLiziDzPa9doObwPCKcNLE%3D&openid.signed=assoc_handle%2Cclaimed_id%2Cidentity%2Cmode%2Cns%2Cop_endpoint%2Cresponse_nonce%2Creturn_to%2Csigned");
                is $res->code, 400 or diag $res->as_string;
                like $res->content, qr!\AERROR: Return_to signature is stale\b!m;
            };

            subtest 'no param' => sub {
                my $res = $cb->(GET '/openid/callback');
                is $res->code, 400 or diag $res->as_string;
                is $res->content, 'Not an OpenID message';
            };

            subtest 'setup needed' => sub {
                my $res = $cb->(GET "/openid/callback?oic.time=$oic_time&openid.assoc_handle=%7BHMAC-SHA1%7D%7B57956479%7D%7BVL%2BPMg%3D%3D%7D&openid.claimed_id=http%3A%2F%2Fexample.com%2Fopen_id&openid.identity=http%3A%2F%2Fexample.com%2Fopen_id&openid.mode=setup_needed&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.op_endpoint=http%3A%2F%2Fexample.com%2Fserver&openid.response_nonce=@{[ time ]}&openid.return_to=http%3A%2F%2Flocalhost%2Fopenid%2Fcallback%3Foic.time%3D${oic_time}&openid.sig=z90DnnLiziDzPa9doObwPCKcNLE%3D&openid.signed=assoc_handle%2Cclaimed_id%2Cidentity%2Cmode%2Cns%2Cop_endpoint%2Cresponse_nonce%2Creturn_to%2Csigned");
                is $res->code, 400 or diag $res->as_string;
                is $res->content, 'Not valid an OpenID message';
            };

            subtest 'canceled' => sub {
                my $res = $cb->(GET '/openid/callback?openid.mode=cancel');
                is $res->code, 302 or diag $res->as_string;
                is $res->header('Location'), '/canceled';
            };
        };
    };
};

done_testing;
