requires 'LWPx::ParanoidHandler';
requires 'Net::OpenID::Consumer';
requires 'Plack::Middleware';
requires 'Plack::Request';
requires 'Plack::Util::Accessor';
requires 'Scalar::Util';
requires 'URI';
requires 'parent';
requires 'perl', '5.008001';

on configure => sub {
    requires 'Module::Build::Tiny', '0.035';
};

on test => sub {
    requires 'HTTP::Message::PSGI';
    requires 'HTTP::Request::Common';
    requires 'LWPx::ParanoidAgent';
    requires 'Plack::Test';
    requires 'Test::Builder::Module';
    requires 'Test::Mock::LWP::Conditional';
    requires 'Test::More', '0.98';
};
