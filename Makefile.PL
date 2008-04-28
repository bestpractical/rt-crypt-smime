use inc::Module::Install;

RTx('RT-Crypt-SMIME');
author ('Jesse Vincent <jesse@bestpractical.com>');
version_from ('lib/RT/Crypt/SMIME.pm');
abstract_from('lib/RT/Crypt/SMIME.pm');
license('perl');
requires('Test::More');
requires('Hook::LexWrap');
requires('IPC::Run3');
requires('String::ShellQuote');
requires('File::Temp');

&WriteAll;
