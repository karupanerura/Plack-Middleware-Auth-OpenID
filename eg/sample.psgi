use strict;
use warnings;

use Plack::Builder;
use Data::Dumper ();
use Cache::LRU;

sub dumper {
    local $Data::Dumper::Terse    = 1;
    local $Data::Dumper::Useqq    = 1;
    local $Data::Dumper::Sortkeys = 1;
    local $Data::Dumper::Deparse  = 1;
    return Data::Dumper::Dumper(@_);
}

my $app = sub {
    my $env = shift;
    return [200, ['Content-Type' => 'text/html'], [<<__BODY__]];
<!DOCTYPE html>
<html>
  <head><title>OpenID Test</title></head>
  <body>
    <form method="POST" action="/openid/authorize">
      <label>URL: <input type="url" name="open_id" /></label>
      <input type="submit" value="Authorize" />
    </form>
    <pre>@{[ dumper($env) ]}</pre>
  </body>
</html>
__BODY__
};

builder {
    enable 'Auth::OpenID',
        debug           => 1,
        consumer_secret => '......................',
        cache           => Cache::LRU->new,
        origin          => 'http://localhost:5000/',
        delayed_return  => 1,
        on_verified     => sub {
            my ($env, $vident, $respond) = @_;
            $env->{'verified.openid.url'} = $vident->url;
        },
        on_error => sub {
            my ($env, $errcode, $errtext, $respond) = @_;
            die "Error validating identity: $errcode: $errtext";
        };

    $app;
};
__END__
