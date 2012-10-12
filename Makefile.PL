use inc::Module::Install;

RTx('RT-Crypt-SMIME');
author ('Jesse Vincent <jesse@bestpractical.com>');
all_from ('lib/RT/Crypt/SMIME.pm');
readme_from('lib/RT/Crypt/SMIME.pm');
license('perl');
requires('Test::More');
requires('Hook::LexWrap');
requires('IPC::Run3');
requires('String::ShellQuote');
requires('File::Temp');

{
    my @v = split /\./, "$RT::VERSION";
    unless ($v[0] == 3 && $v[1] == 6) {
        die "\n\nRT-Crypt-SMIME only works on RT 3.6.x (you have $RT::VERSION).\n\n\n";
    }
}

sign();
&WriteAll;
