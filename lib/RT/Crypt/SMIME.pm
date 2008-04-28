package RT::Crypt::SMIME;

our $VERSION = '0.22';

use warnings;
use strict;
use Carp;
use Hook::LexWrap;
use IPC::Run3 0.036 'run3';
use String::ShellQuote 'shell_quote';
use File::Temp;
use IO::Handle ();

=head1 NAME

RT::Crypt::SMIME - An RT extension to perform S/MIME encryption and decryption for mail RT sends


=head1 SYNOPSIS

    # In your RT_SiteConfig.pm, add the following configuration directives
    use RT::Crypt::SMIME;
    Set($OpenSSLPath, '/usr/bin/openssl'); # or wherever openssl lives
    Set($SMIMEKeys, '/opt/rt3/etc'); # This directory should contain RT's private keys and certificates in address.pem files
    Set($SMIMEPasswords, { address => 'squeamish ossifrage'); # The private passphrases for RT's private keys
    @MailPlugins = (qw(Auth::MailFrom Auth::SMIME));

=head1 DESCRIPTION


=head1 METHODS

=cut

use RT;
use RT::Action::SendEmail;

our $NO_ENCRYPTION = 0;

if ( my $real = RT::Interface::Email->can('SendEmail') ) {    # 3.7
    wrap RT::Interface::Email::SendEmail, pre => sub {
        return if $NO_ENCRYPTION;
        my (%args) = (
            Entity      => undef,
            Bounce      => 0,
            Ticket      => undef,
            Transaction => undef,
            splice( @_, 0, $#_ ),
        );
        my $mime = $args{Entity};

        my $mime_copy = encrypt_message( $args{Ticket}, $mime->dup );

        $_[-1] = $real->( %args, $mime_copy ? ( Entity => $mime_copy ) : () );
    };
}
else {    # 3.6
    wrap RT::Action::SendEmail::OutputMIMEObject, pre => sub {
        return if $NO_ENCRYPTION;
        my $self      = $_[0];
        my $mime      = $_[1];
        my $mime_copy = encrypt_message( $self->TicketObj, $mime->dup );
        $_[1] = $mime_copy if $mime_copy;
    };
}

sub encrypt_message {
    my $ticket   = shift;
    my $mime_obj = shift;
    my ($addr)   = map { $_->address } Mail::Address->parse( $mime_obj->head->get('From') );

    # extract recipients from each header
    my %headers;
    foreach my $header (qw(To Cc Bcc)) {
        @{ $headers{$header} } = map { $_->address }
            Mail::Address->parse( $mime_obj->head->get($header) );
    }

    my @keys;
    foreach my $header ( keys %headers ) {
        # Splice all addresses from a list and then add them back if everything is fine
        foreach my $addr ( splice @{ $headers{$header} } ) {
            chomp $addr;
            $RT::Logger->debug( "Considering encrypting message to " . $addr );
            my $user = RT::User->new( $RT::SystemUser );
            $user->LoadByEmail( $addr );
            my $key;
            $key = $user->FirstCustomFieldValue('PublicKey') if ( $user->id );
            unless ( $key ) {
                $RT::Logger->error(
                    "Trying to send an encrypted message to " . $addr
                    .", but we couldn't find a public key or user object for them"
                );

                # send the user a special message template that contains
                # only a URL and the note that their key isn't set up
                send_message( $ticket, $addr, 'NoPublicKey' );
                next;
            }

            my $expire = get_expiration( $user );
            unless ( $expire ) {
                # we continue here as it's most probably a problem with the key,
                # so later during encryption we'll get verbose errors
                $RT::Logger->error(
                    "Trying to send an encrypted message to ". $addr
                    .", but we couldn't get expiration date of the key."
                );
            }
            elsif ( $expire->Diff( time ) < 0 ) {
                $RT::Logger->error(
                    "Trying to send an encrypted message to " . $addr
                    .", but the key is expired"
                );
                send_message( $ticket, $addr, 'ExpiredPublicKey' );
                next;
            }

            $RT::Logger->debug( "Encrypting to " . $addr );

            my $user_crt = File::Temp->new;
            print $user_crt $key;

            push @keys, $user_crt;
            push @{ $headers{ $header } }, $addr;
        }
    }

    foreach my $header ( keys %headers ) {
        $mime_obj->head->replace( $header,
            join( ', ', @{ $headers{$header} } ) );
    }
    return unless @keys;

    $mime_obj->make_multipart('mixed', Force => 1);
    my ($buf, $err) = ('', '');
    {
        local $ENV{SMIME_PASS} = $RT::SMIMEPasswords->{$addr};
        safe_run3(
            join(
                ' ',
                shell_quote(
                    $RT::OpenSSLPath,
                    qw( smime -sign -passin env:SMIME_PASS),
                    -signer => $RT::SMIMEKeys.'/'.$addr.'.pem',
                    -inkey  => $RT::SMIMEKeys.'/'.$addr.'.pem',
                ),
                '|',
                shell_quote(
                    qw(openssl smime -encrypt -des3),
                    map { $_->filename } @keys
                )
            ),
            \$mime_obj->parts(0)->stringify,
            \$buf, \$err
        );
    }
    $RT::Logger->debug( "openssl stderr: " . $err ) if length $err;

    my $tmpdir = File::Temp::tempdir( TMPDIR => 1, CLEANUP => 1 );
    my $parser  = MIME::Parser->new();
    $parser->output_dir($tmpdir);
    my $newmime = $parser->parse_data($buf);
    $mime_obj->parts([$newmime]);
    $mime_obj->make_singlepart;
    return $mime_obj;

}

sub safe_run3 {
    # We need to reopen stdout temporarily, because in FCGI
    # environment, stdout is tied to FCGI::Stream, and the child
    # of the run3 wouldn't be able to reopen STDOUT properly.
    my $stdout = IO::Handle->new;
    $stdout->fdopen( 1, 'w' );
    local *STDOUT = $stdout;

    my $stderr = IO::Handle->new;
    $stderr->fdopen( 2, 'w' );
    local *STDERR = $stderr;

    local $SIG{'CHLD'} = 'DEFAULT';
    run3(@_);
}

sub send_message {
    my ($ticket, $to, $template_name) = (@_);

    my $template = RT::Template->new( $RT::SystemUser );
    $template->LoadGlobalTemplate( $template_name );
    unless ( $template->id ) {
        $RT::Logger->error( "Couldn't load template '$template_name'");
        return;
    }
    $template->Parse( TicketObj => $ticket );
    my $sorry_dude = $template->MIMEObj;
    $sorry_dude->head->set( To => $to );

    local $NO_ENCRYPTION = 1;
    return RT::Interface::Email->can('SendEmail')
        ? RT::Interface::Email::SendEmail( Entity => $sorry_dude )
        : RT::Action::SendEmail->OutputMIMEObject($sorry_dude);
}

sub get_expiration {
    my $user = shift;

    my $key_obj = $user->CustomFieldValues('PublicKey')->First;
    unless ( $key_obj ) {
        $RT::Logger->warn('User #'. $user->id .' has no SMIME key');
        return;
    }

    my $attr = $user->FirstAttribute('SMIMEKeyNotAfter');
    if ( $attr and my $date_str = $attr->Content
         and $key_obj->LastUpdatedObj->Unix < $attr->LastUpdatedObj->Unix )
    {
        my $date = RT::Date->new( $RT::SystemUser );
        $date->Set( Format => 'unknown', Value => $attr->Content );
        return $date;
    }
    $RT::Logger->debug('Expiration date of SMIME key is not up to date');

    my $key = $key_obj->Content;
    my ($buf, $err) = ('', '');
    {
        local $ENV{SMIME_PASS} = '123456';
        safe_run3(
            join( ' ', shell_quote( $RT::OpenSSLPath, qw(x509 -noout -dates) ) ),
            \$key, \$buf, \$err
        );
    }
    $RT::Logger->debug( "openssl stderr: " . $err ) if length $err;

    my ($date_str) = ($buf =~ /^notAfter=(.*)$/m);
    return unless $date_str;

    $RT::Logger->debug( "smime key expiration date is $date_str" );
    $user->SetAttribute(
        Name => 'SMIMEKeyNotAfter',
        Description => 'SMIME key expiration date',
        Content => $date_str,
    );
    my $date = RT::Date->new( $RT::SystemUser );
    $date->Set( Format => 'unknown', Value => $date_str );
    return $date;
}

=head1 AUTHOR

Jesse Vincent  C<< <jesse@bestpractical.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006, Best Practical Solutions, LLC. 

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

=cut

1;
