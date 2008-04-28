use IPC::Run3 'run3';
use String::ShellQuote 'shell_quote';
use File::Temp;

my $signer = 'testkeys/sender';
my $out = File::Temp->new;
{
    local $ENV{SMIME_PASS} = '123456';
    run3( join( ' ',
            shell_quote(
                qw(openssl smime -sign -passin env:SMIME_PASS -text),
                -signer => $signer . '.crt',
                -inkey  => $signer . '.key'
            ),
            '|',
            shell_quote(
                qw(openssl smime -encrypt  -des3),
                -from    => 'steve@openssl.org',
                -to      => 'someone@somewhere',
                -subject => "Signed and Encrypted message",
                'testkeys/recipient.crt'
            )
        ),
        \'orzzzzzz',
        \*STDOUT,
        \*STDERR
    );
}
