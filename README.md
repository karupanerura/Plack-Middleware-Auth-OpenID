# NAME

Plack::Middleware::Auth::OpenID - It's new $module

# SYNOPSIS

    use Plack::Builder;
    use Plack::Session;
    use Cache::Memcached::Fast;
    use LWPx::ParanoidAgent;

    builder {
        enable 'Session', ....;
        enable 'Auth::OpenID',
            consumer_secret => '...',
            cache => Cache::Memcached::Fast->new(...),
            origin => 'https://example.com/',
            ua => LWPx::ParanoidAgent->new(
                whitelisted_hosts => [qw/hoge.net/],
            ),
            on_verified => sub {
                my ($env, $vident, $respond) = @_;
                my $session = Plack::Session->new($env);
                $session->set(vaild_open_id => $vident->url);
                $session->options->{change_id}++;
                $respond->(302, ['Location' => '/path/to/protected'], []);
            },
            on_error => sub {
                my ($env, $errcode, $errtext, $respond) = @_;
                die "Error validating identity: $errcode: $errcode";
                # or $respond->(302, ['Location' => "/path/to/error?errcode=$errcode"], []);
            };

        $app;
    };

# DESCRIPTION

Plack::Middleware::Auth::OpenID is ...

# LICENSE

Copyright (C) karupanerura.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

karupanerura <karupa@cpan.org>
