requires 'CryptX';
requires 'Moo';
requires 'namespace::clean';
requires 'Ouch';

on test => sub {
    requires 'Test::More';
    requires 'Test::Exception';
};
