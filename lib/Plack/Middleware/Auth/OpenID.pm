package Plack::Middleware::Auth::OpenID;
use 5.008001;
use strict;
use warnings;

our $VERSION = "0.01";

use parent qw/Plack::Middleware/;
use Plack::Util::Accessor qw/openid_param delayed_return origin authenticate_path callback_path cancel_path on_verified on_error/;
use Plack::Util::Accessor grep !/^(?:args|required_root)$/, keys %Net::OpenID::Consumer::FIELDS;

use Scalar::Util qw/blessed/;
use URI;
use Plack::Request;
use Net::OpenID::Consumer;

sub prepare_app {
    my $self = shift;
    $self->$_ or die "no required parameter: $_" for qw/origin on_verified on_error/;

    unless ($self->openid_param) {
        $self->openid_param('open_id');
    }
    unless ($self->authenticate_path) {
        $self->authenticate_path('/openid/authenticate');
    }
    unless ($self->callback_path) {
        $self->callback_path('/openid/callback');
    }
    unless ($self->cancel_path) {
        $self->cancel_path('/');
    }
    $self->origin(URI->new($self->origin)) unless blessed $self->origin && $self->origin->isa('URI');
}

sub callback_url {
    my $self = shift;

    my URI $return_to = $self->origin->clone();
    $return_to->path_query($self->callback_path);
    return $return_to;
}

sub _make_csr {
    my ($self, $req) = @_;

    my %fields = map { $_ => $self->{$_} } grep { exists $self->{$_} } keys %Net::OpenID::Consumer::FIELDS;
    my Net::OpenID::Consumer $csr = Net::OpenID::Consumer->new(
        args          => $req,
        required_root => $self->origin,
        %fields,
    );

    # make it as paranoid
    if (!$csr->ua->isa('LWPx::ParanoidAgent') && $csr->ua->isa('LWP::UserAgent')) {
        require LWPx::ParanoidHandler;
        LWPx::ParanoidHandler::make_paranoid($csr->ua);
    }

    return $csr;
}

sub call {
    my ($self, $env) = @_;

    if ($env->{PATH_INFO} eq $self->authenticate_path) {
        return $self->handle_authenticate($env);
    }
    elsif ($env->{PATH_INFO} eq $self->callback_path) {
        my $res = $self->handle_callback($env);
        return $res if ref $res;
    }

    return $self->app->($env);
}

sub handle_authenticate {
    my ($self, $env) = @_;
    return $self->res_405 if $env->{REQUEST_METHOD} ne 'POST';

    my Plack::Request $req = Plack::Request->new($env);
    my Net::OpenID::Consumer $csr = $self->_make_csr($req);

    my $open_id = $req->parameters->get($self->openid_param);
    unless (defined $open_id) {
        return $self->res_400("parameter @{[ $self->openid_param ]} is required");
    }

    my Net::OpenID::ClaimedIdentity $claimed_identity = $csr->claimed_identity($open_id);
    unless ($claimed_identity) {
        return $self->res_400("not actually an openid?  " . $csr->err);
    }

    my $redirect_url = $claimed_identity->check_url(
        return_to      => $self->callback_url,
        trust_root     => $self->origin,
        delayed_return => $self->delayed_return,
    );
    return $self->redirect($redirect_url);
}

sub handle_callback {
    my ($self, $env) = @_;
    return $self->res_405 if $env->{REQUEST_METHOD} ne 'GET';

    my Plack::Request $req = Plack::Request->new($env);
    my Net::OpenID::Consumer $csr = $self->_make_csr($req);
    return $csr->handle_server_response(
        not_openid => sub {
            return $self->res_400('Not an OpenID message');
        },
        setup_needed => sub {
            if ($csr->message->protocol_version >= 2) {
                return $self->res_400('Not valid an OpenID message');
            }
            else {
                return $self->redirect($csr->user_setup_url);
            }
        },
        cancelled => sub {
            return $self->redirect($self->cancel_path);
        },
        verified => sub {
            my $vident = shift;

            my $res;
            $self->on_verified->($env, $vident, sub { $res = [@_] });
            return $res;
        },
        error => sub {
            my ($errcode, $errtext) = @_;

            my $res;
            $self->on_error->($env, $errcode, $errtext, sub { $res = [@_] });
            return $res;
        },
    );
}

sub redirect {
    my ($self, $url) = @_;
    return [
        302,
        ['Location' => $url],
        [],
    ];
}

sub res_400 {
    my ($self, $message) = @_;
    return [
        400,
        ['Content-Type' => 'text/plain'],
        [$message || 'Bad Request'],
    ];
}

sub res_405 {
    my ($self, $message) = @_;
    return [
        405,
        ['Content-Type' => 'text/plain'],
        [$message || 'Method Not Allowed'],
    ];
}

1;
__END__

=encoding utf-8

=head1 NAME

Plack::Middleware::Auth::OpenID - It's new $module

=head1 SYNOPSIS

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

=head1 DESCRIPTION

Plack::Middleware::Auth::OpenID is ...

=head1 LICENSE

Copyright (C) karupanerura.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

karupanerura E<lt>karupa@cpan.orgE<gt>

=cut

