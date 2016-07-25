package t::Util;
use strict;
use warnings;

use parent qw/Test::Builder::Module/;

use Test::Mock::LWP::Conditional;
use Net::OpenID::Consumer;
use LWPx::ParanoidAgent (); # required for test
use Plack::Middleware::Auth::OpenID;
use Plack::Request;
use HTTP::Message::PSGI ();

sub _on_verified { __PACKAGE__->builder->ok(1, "VERIFIED: ".$_[1]->url) }
sub _on_error    { pop->(400, [], ["ERROR: $_[2]"]) }

sub create_middleware {
    my ($class, %args) = @_;
    return Plack::Middleware::Auth::OpenID->new(
        consumer_secret => 'DUMMY CONSUMER SECRET',
        cache           => undef,
        origin          => 'http://localhost/',
        on_verified     => \&_on_verified,
        on_error        => \&_on_error,
        debug           => sub { __PACKAGE__->builder->note(@_) },
        %args,
    );
}

sub create_app {
    my $class = shift;
    return $class->create_middleware(@_)->wrap(sub {
        my $env = shift;
        return [200, [], [$env->{REQUEST_METHOD}.' '.$env->{PATH_INFO}]];
    });
}

sub mock_for_open_id_v2 {
    Test::Mock::LWP::Conditional->stub_request(
        "http://example.com/invalid_open_id" => sub {
            my $req = shift;
            my $res = HTTP::Response->new(404);
            $res->request($req);
            return $res;
        },
    );
    Test::Mock::LWP::Conditional->stub_request(
        "http://example.com/open_id" => sub {
            my $req = shift;
            my $res = HTTP::Response->new(204);
            $res->request($req);
            $res->header('X-XRDS-Location' => 'http://example.com/xrds');
            return $res;
        },
    );
    Test::Mock::LWP::Conditional->stub_request(
        "http://example.com/xrds" => sub {
            my $req = shift;
            my $res = HTTP::Response->new(200);
            $res->request($req);
            $res->header('Content-Type' => 'application/xrds+xml');
            $res->content(<<'__BODY__');
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <URI>http://example.com/server</URI>
    </Service>
  </XRD>
</xrds:XRDS>
__BODY__
            return $res;
        },
    );
    Test::Mock::LWP::Conditional->stub_request(
        "http://example.com/server" => sub {
            my $original_request = shift;
            my $req = Plack::Request->new($original_request->to_psgi);

            if ($req->method eq 'POST') {
                my $mode = $req->parameters->get('openid.mode');
                if ($mode eq 'associate') {
                    my $res = _emulate_associate_v2($req);
                    return HTTP::Response->from_psgi($res);
                }
                elsif ($mode eq 'check_authentication') {
                    my $res = _emulate_checking_authentication_v2($req);
                    return HTTP::Response->from_psgi($res);
                }
            }

            die "Unknown request:\n", $original_request->as_string;
        },
    );
}

sub _emulate_associate_v2 {
    my $req = shift;
    my $body = <<'__BODY__';
ns:http://specs.openid.net/auth/2.0
assoc_handle:W1ZkMy1HiOoijMrB2IMLL_PIHR3oTyFWRtdVR7CAnVEuxHDnNtvwQEuAh0mUvrHUYUPkETTTtaKB_ixyDmWWw3jWTDgy6sTHIdSmrlzzAtpRNWXWZTKZUxZjZQwEeNxopA--
session_type:DH-SHA1
assoc_type:HMAC-SHA1
expires_in:14400
enc_mac_key:0NR9k1ZMA+fFL7btQRIKgk2T43I=
dh_server_public:cPdWqtLhRpzozMHDPOUR7qNYeSezzyS0rjESCMBbZ9/kPWxdyQN/S05m+Oh27dqqtYvigwlEy0ht7UqmiE2kVHqj4pjiqz2xMq4e7nEwCpYynuwInhuAl77mIevy908fuVEyCessfebXOu/59faG5xHqX6ta1Ir8/rOmGRw0cxs=
__BODY__
    return [
        200,
        ['Content-Type' => 'text/plain'],
        [$body],
    ]
}

sub _emulate_checking_authentication_v2 {
    my $req = shift;
    my $body = <<'__BODY__';
ns:http://specs.openid.net/auth/2.0
is_valid:true
__BODY__
    return [
        200,
        ['Content-Type' => 'text/plain'],
        [$body],
    ]
}

1;
__END__
